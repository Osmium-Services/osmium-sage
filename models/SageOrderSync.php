<?php

declare(strict_types=1);

namespace Osmium\Services\Sage\Models;

/**
 * Sage's side of the admin order page: the sidebar panel (order.panels hook)
 * and the "Push to Sage" action (order.action hook). Pushing is manual and
 * creates a real posted invoice, so it is guarded by the
 * allowedBusinessName lock.
 */
class SageOrderSync
{
    private const ACTION = 'push_to_sage';
    private const PUSHABLE_STATUSES = ['paid', 'dispatched', 'refunded'];

    /**
     * order.panels handler.
     *
     * @param array{order: array, osmium: object} $payload
     */
    public static function orderPanel(array $payload): string
    {
        $order = $payload['order'];
        $invoice = self::findInvoice($payload['osmium']->dataSource, (int) $order['id']);

        $sage = [
            'synced' => $invoice !== null,
            'syncedAt' => $invoice['synced_at'] ?? null,
            'invoiceNumber' => $invoice['invoice_number'] ?? null,
            'canPush' => $invoice === null && \in_array($order['status'], self::PUSHABLE_STATUSES, true),
        ];

        $cspNonce = \Osmium\Core\OsmiumSecurity::requestNonce(); // The view's inline script is blocked without it

        \ob_start();
        require __DIR__ . '/../views/sage/order-panel.phtml';

        return (string) \ob_get_clean();
    }

    /**
     * order.action handler. Returns null for actions that aren't ours.
     *
     * @param array{action: string, orderId: int, input: array, osmium: object, admin?: object} $payload
     * @throws \RuntimeException when the push is refused or fails
     */
    public static function orderAction(array $payload): ?array
    {
        $notOurs = $payload['action'] !== self::ACTION;
        if ($notOurs) return null;

        $osmium = $payload['osmium'];
        $db = $osmium->dataSource;
        $orderId = $payload['orderId'];

        $order = self::loadOrder($db, $orderId);
        $orderMissing = $order === null;
        if ($orderMissing) throw new \RuntimeException('Order not found.');

        $alreadySynced = self::findInvoice($db, $orderId) !== null;
        if ($alreadySynced) throw new \RuntimeException('This order has already been pushed to Sage.');

        $notPushable = !\in_array($order['status'], self::PUSHABLE_STATUSES, true);
        if ($notPushable) throw new \RuntimeException('Only a paid order can be pushed to Sage.');

        $sage = SageConfig::buildService($db);
        self::assertBusinessAllowed($sage);

        $config = SageConfig::get();
        $ledgerAccountId = (string) $config->ledgerAccountId;
        $taxRateId = (string) $config->taxRateId;

        $notSetUp = $ledgerAccountId === '' || $taxRateId === '';
        if ($notSetUp) throw new \RuntimeException('Choose a sales ledger account and a tax rate in the Sage settings before pushing.');

        $taxPercentage = self::findTaxPercentage($sage, $taxRateId);

        $customerId = $sage->findOrCreateCustomer(name: $order['customer_name'], email: $order['customer_email']);

        $lineItems = \array_map(static fn(array $item): array => [
            'description' => $item['product_title'],
            'quantity' => (float) $item['quantity'],
            'unitAmount' => (float) $item['unit_price_exc_tax'],
        ], self::loadItems($db, $orderId));

        $hasShipping = (float) $order['shipping_amount'] > 0;
        if ($hasShipping) {
            $lineItems[] = [
                'description' => 'Delivery',
                'quantity' => 1,
                'unitAmount' => (float) $order['shipping_amount'],
            ];
        }

        $invoiceDate = \substr((string) ($order['paid_at'] ?? $order['created_at']), 0, 10);

        $invoice = $sage->createInvoice(
            customerId: $customerId,
            lineItems: $lineItems,
            ledgerAccountId: $ledgerAccountId,
            taxRateId: $taxRateId,
            taxPercentage: $taxPercentage,
            reference: $order['order_ref'],
            invoiceDate: $invoiceDate,
        );

        self::recordInvoice($db, $orderId, $invoice);

        $admin = $payload['admin'] ?? null;
        if ($admin !== null) {
            $admin->model->changelog->log(
                description: "Pushed order {$order['order_ref']} to Sage as invoice {$invoice['invoiceNumber']}",
                recordType: 'order',
                recordId: $orderId,
            );
        }

        return [
            'success' => true,
            'action' => self::ACTION,
            'id' => $orderId,
            'sage_invoice_id' => $invoice['invoiceId'],
            'sage_invoice_number' => $invoice['invoiceNumber'],
        ];
    }

    /**
     * Hard safety gate: a push creates a real invoice in whatever Sage
     * business is connected, so it is refused unless the connected
     * business's name matches the one deliberately confirmed in settings.
     */
    private static function assertBusinessAllowed(SageService $sage): void
    {
        $allowedName = \trim((string) SageConfig::get()->allowedBusinessName);
        $connectedName = $sage->getConnection()['business_name'] ?? null;

        $noAllowedName = $allowedName === '';
        if ($noAllowedName) {
            throw new \RuntimeException(
                'Sage pushing is locked: no allowed business is set. Confirm which Sage business is connected (currently "'
                . ($connectedName ?? 'none') . '") in the Sage settings before pushing.'
            );
        }

        $mismatch = $connectedName !== $allowedName;
        if ($mismatch) {
            throw new \RuntimeException(
                "Sage pushing is locked to \"{$allowedName}\", but the connected business is \""
                . ($connectedName ?? 'none') . '". Refusing to push.'
            );
        }
    }

    /**
     * The chosen tax rate's percentage, read from Sage so it is never stale.
     */
    private static function findTaxPercentage(SageService $sage, string $taxRateId): float
    {
        foreach ($sage->listTaxRates() as $rate) {
            $isChosen = $rate['id'] === $taxRateId;
            if ($isChosen) return (float) $rate['percentage'];
        }

        throw new \RuntimeException('The tax rate chosen in the Sage settings no longer exists in Sage.');
    }

    private static function findInvoice(\Osmium\Core\Library\OsmiumPDO $db, int $orderId): ?array
    {
        $db->query("SELECT invoice_id, invoice_number, synced_at FROM {$db->tablePrefix()}sage_invoices WHERE order_id = :id LIMIT 1");
        $db->bind(param: ':id', value: $orderId);

        return $db->single() ?: null;
    }

    private static function recordInvoice(\Osmium\Core\Library\OsmiumPDO $db, int $orderId, array $invoice): void
    {
        $db->query(
            "INSERT INTO {$db->tablePrefix()}sage_invoices (order_id, invoice_id, invoice_number) "
            . 'VALUES (:order_id, :invoice_id, :invoice_number)'
        );
        $db->bind(param: ':order_id', value: $orderId);
        $db->bind(param: ':invoice_id', value: $invoice['invoiceId']);
        $db->bind(param: ':invoice_number', value: $invoice['invoiceNumber']);
        $db->execute();
    }

    private static function loadOrder(\Osmium\Core\Library\OsmiumPDO $db, int $orderId): ?array
    {
        $db->query("SELECT * FROM {$db->tablePrefix()}shop_orders WHERE id = :id LIMIT 1");
        $db->bind(param: ':id', value: $orderId);

        return $db->single() ?: null;
    }

    private static function loadItems(\Osmium\Core\Library\OsmiumPDO $db, int $orderId): array
    {
        $db->query("SELECT * FROM {$db->tablePrefix()}shop_order_items WHERE order_id = :id ORDER BY id ASC");
        $db->bind(param: ':id', value: $orderId);

        return $db->resultset();
    }
}
