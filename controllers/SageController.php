<?php

declare(strict_types=1);

namespace Osmium\Services\Sage\Controllers;

use Osmium\Modules\Admin\Core\AdminController;
use Osmium\Services\Sage\Models\SageConfig;
use Osmium\Services\Sage\Models\SageService;

/**
 * Sage settings controller - credentials, OAuth2 connection and status.
 *
 * Routes:
 *   - index()    → /admin/settings/sage/           (status + settings form)
 *   - connect()  → /admin/settings/sage/connect/   (redirects to Sage)
 *   - callback() → /admin/settings/sage/callback/  (Sage redirects back here)
 *   - action()   → /admin/settings/sage/action/    (disconnect, test_connection)
 */
class SageController extends AdminController
{
    private const STATE_SESSION_KEY = 'sage_oauth_state';
    private const FLASH_KEY = 'sage_flash';

    public function index(): void
    {
        $isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
        if ($isPost) $this->handleSubmit();

        $error = $this->osmium->getStashedParam(key: 'error', default: null);
        $justConnected = $this->osmium->getStashedParam(key: 'connected', default: null);
        $this->osmium->clearStashedQuerystring();

        $config = (array) SageConfig::get();
        $connection = $this->sage()->getConnection();
        $lookups = $this->loadLookups(connected: $connection !== null);

        $this->data['admin']['sage'] = [
            'clientId' => $config['clientId'],
            'hasSecret' => $config['clientSecret'] !== '',
            'redirectUri' => $config['redirectUri'] ?: $this->suggestedRedirectUri(),
            'country' => $config['country'],
            'ledgerAccountId' => $config['ledgerAccountId'],
            'taxRateId' => $config['taxRateId'],
            'ledgerAccounts' => $lookups['ledgerAccounts'],
            'taxRates' => $lookups['taxRates'],
            'lookupError' => $lookups['error'],
            'allowedBusinessName' => $config['allowedBusinessName'],
            'clientConfigured' => $config['clientId'] !== '' && $config['clientSecret'] !== '',
            'connected' => $connection !== null,
            'businessName' => $connection['business_name'] ?? null,
            'connectedAt' => $connection['connected_at'] ?? null,
            'error' => $error,
            'justConnected' => $justConnected !== null,
        ];
        $this->data['admin']['flash'] = $_SESSION[self::FLASH_KEY] ?? null;
        unset($_SESSION[self::FLASH_KEY]);

        $this->setView('sage/index.phtml');
    }

    /**
     * Start the OAuth2 flow - redirects the admin to Sage's consent screen.
     */
    public function connect(): void
    {
        $state = \bin2hex(\random_bytes(16));
        $_SESSION[self::STATE_SESSION_KEY] = $state;

        $this->osmium->header->redirect(targetURL: $this->sage()->getAuthorizationUrl(state: $state));
    }

    /**
     * OAuth2 redirect target - exchanges the code Sage sent back for tokens.
     */
    public function callback(): void
    {
        // Sage's ?code=&state= never reach $_GET here - the framework's global
        // stashQuerystring() already stripped them into $_SESSION['qs'] and
        // 302'd to this same clean URL before this method ever runs.
        $returnedState = (string) $this->osmium->getStashedParam(key: 'state', default: '');
        $error = (string) $this->osmium->getStashedParam(key: 'error', default: '');
        $code = (string) $this->osmium->getStashedParam(key: 'code', default: '');
        $this->osmium->clearStashedQuerystring();

        $expectedState = $_SESSION[self::STATE_SESSION_KEY] ?? '';
        unset($_SESSION[self::STATE_SESSION_KEY]);

        $stateInvalid = empty($expectedState) || !\hash_equals($expectedState, $returnedState);
        if ($stateInvalid) $this->redirect('settings/sage/?error=' . \rawurlencode('Invalid OAuth state'));

        if ($error) $this->redirect('settings/sage/?error=' . \rawurlencode($error));

        $codeMissing = empty($code);
        if ($codeMissing) $this->redirect('settings/sage/?error=' . \rawurlencode('No authorization code returned'));

        try {
            $this->sage()->completeAuthorization(code: $code);
        } catch (\Exception $e) {
            $this->redirect('settings/sage/?error=' . \rawurlencode($e->getMessage()));
        }

        $this->redirect('settings/sage/?connected=1');
    }

    /**
     * Action endpoint - disconnect and test_connection.
     */
    public function action()
    {
        \header('Content-Type: application/json');

        $isPostMethod = $_SERVER['REQUEST_METHOD'] === 'POST';
        if (!$isPostMethod) $this->admin->jsonError('Method not allowed');

        $input = $this->admin->auth->getJsonInput();
        $action = $input['action'] ?? '';

        $invalidToken = !$this->admin->auth->validateCsrfJson($input);
        if ($invalidToken) {
            $this->admin->jsonError('Invalid request token. Please refresh the page and try again.');
        }

        match ($action) {
            'test_connection' => $this->testConnection(),
            'disconnect' => $this->disconnect(),
            default => $this->admin->jsonError('Unknown action'),
        };
    }

    private function handleSubmit(): void
    {
        $csrfValid = $this->admin->auth->validateCsrf();
        if (!$csrfValid) $this->flashAndRedirect('danger', 'Invalid form submission. Please try again.');

        $current = SageConfig::get();

        $postedSecret = \trim($_POST['client_secret'] ?? '');
        $clientSecret = $postedSecret === '' ? (string) $current->clientSecret : $postedSecret; // Blank keeps the stored secret

        SageConfig::save([
            'clientId' => \trim($_POST['client_id'] ?? ''),
            'clientSecret' => $clientSecret,
            'redirectUri' => \trim($_POST['redirect_uri'] ?? ''),
            'country' => \in_array($_POST['country'] ?? '', ['gb', 'ie', 'ca'], true) ? $_POST['country'] : 'gb',
            'ledgerAccountId' => \trim($_POST['ledger_account_id'] ?? ''),
            'taxRateId' => \trim($_POST['tax_rate_id'] ?? ''),
            'allowedBusinessName' => \trim($_POST['allowed_business_name'] ?? ''),
        ]);

        $this->admin->model->changelog->log(
            description: 'Updated Sage settings',
            recordType: 'settings',
        );

        $this->flashAndRedirect('success', 'Settings saved successfully!');
    }

    private function testConnection(): void
    {
        $result = $this->sage()->testConnection();

        if ($result['success']) {
            $this->admin->jsonSuccess($result);
        }

        $this->admin->jsonError($result['message']);
    }

    private function disconnect(): void
    {
        $this->sage()->disconnect();

        $this->admin->model->changelog->log(
            description: 'Disconnected Sage',
            recordType: 'sage_connection',
            recordId: 0,
        );

        $this->admin->jsonSuccess(['success' => true]);
    }

    /**
     * The ledger accounts and tax rates for the settings dropdowns. A failure
     * (expired link, Sage down) shows as a message instead of breaking the page.
     */
    private function loadLookups(bool $connected): array
    {
        $empty = ['ledgerAccounts' => [], 'taxRates' => [], 'error' => null];
        if (!$connected) return $empty;

        try {
            return [
                'ledgerAccounts' => $this->sage()->listSalesLedgerAccounts(),
                'taxRates' => $this->sage()->listTaxRates(),
                'error' => null,
            ];
        } catch (\Exception $e) {
            return ['ledgerAccounts' => [], 'taxRates' => [], 'error' => $e->getMessage()];
        }
    }

    private function sage(): SageService
    {
        return SageConfig::buildService($this->osmium->dataSource);
    }

    private function suggestedRedirectUri(): string
    {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

        return "{$scheme}://{$_SERVER['HTTP_HOST']}{$this->data['admin']['basePath']}settings/sage/callback/";
    }

    private function flashAndRedirect(string $type, string $text): void
    {
        $_SESSION[self::FLASH_KEY] = ['type' => $type, 'text' => $text];
        $this->redirect('settings/sage/');
    }
}
