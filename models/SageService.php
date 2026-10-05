<?php

/**
 * Sage Accounting API Service (Sage Business Cloud Accounting v3.1)
 *
 * Handles OAuth2 connection (authorize, token exchange, refresh) and the
 * accounting calls needed to push a paid order to Sage as a sales invoice.
 *
 * API Documentation: https://developer.sage.com/accounting/
 */

namespace Osmium\Services\Sage\Models;

use Osmium\Core\Library\OsmiumPDO;

class SageService
{
    private const AUTHORIZE_URL = 'https://www.sageone.com/oauth2/auth/central';
    private const TOKEN_URL = 'https://oauth.accounting.sage.com/token';
    private const API_URL = 'https://api.accounting.sage.com/v3.1';
    private const TOKEN_REFRESH_MARGIN_SECONDS = 60; // Access tokens only live 300 seconds

    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private string $country;
    private string $allowedBusinessName;
    private OsmiumPDO $database;
    private string $tablePrefix;

    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        string $country,
        string $allowedBusinessName,
        OsmiumPDO $database,
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->country = $country;
        $this->allowedBusinessName = $allowedBusinessName;
        $this->database = $database;
        $this->tablePrefix = $database->tablePrefix();
    }

    // ----------------------------------------
    // OAuth2 connection flow
    // ----------------------------------------

    /**
     * Build the URL to send the admin to in order to authorize this app.
     */
    public function getAuthorizationUrl(string $state): string
    {
        $query = \http_build_query([
            'filter' => 'apiv3.1',
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'full_access',
            'country' => $this->country,
            'state' => $state,
        ]);

        return self::AUTHORIZE_URL . '?' . $query;
    }

    /**
     * Exchange an authorization code for tokens, pick the Sage business to
     * use, and persist the connection. Called from the OAuth callback.
     *
     * A Sage user can have several businesses. The one whose name matches
     * "Allowed business" is used, otherwise the first one listed.
     */
    public function completeAuthorization(string $code): array
    {
        $tokens = $this->requestToken([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
        ]);

        $business = $this->chooseBusiness(accessToken: $tokens['access_token']);

        $this->saveConnection(
            businessId: $business['id'],
            businessName: $business['name'],
            accessToken: $tokens['access_token'],
            refreshToken: $tokens['refresh_token'],
            expiresIn: (int) $tokens['expires_in'],
        );

        return ['businessId' => $business['id'], 'businessName' => $business['name']];
    }

    /**
     * The currently connected business, or null if never connected.
     */
    public function getConnection(): ?array
    {
        $sql = "SELECT * FROM {$this->tablePrefix}sage_connection ORDER BY id DESC LIMIT 1";
        $this->database->query($sql);

        return $this->database->single() ?: null;
    }

    /**
     * Remove the stored connection. The admin must re-authorize to reconnect.
     */
    public function disconnect(): void
    {
        $sql = "DELETE FROM {$this->tablePrefix}sage_connection";
        $this->database->query($sql);
        $this->database->execute();
    }

    /**
     * @return array ['id', 'name'] of the business to connect to
     * @throws \Exception If the user has no businesses
     */
    private function chooseBusiness(string $accessToken): array
    {
        $response = $this->request(method: 'GET', path: 'businesses', accessToken: $accessToken);
        $businesses = $response['$items'] ?? [];

        $noBusinesses = empty($businesses);
        if ($noBusinesses) throw new \Exception('This Sage user has no businesses');

        $chosen = $businesses[0];
        foreach ($businesses as $business) {
            $nameMatches = ($business['displayed_as'] ?? '') === $this->allowedBusinessName;
            if ($nameMatches) $chosen = $business;
        }

        return ['id' => (string) $chosen['id'], 'name' => (string) $chosen['displayed_as']];
    }

    /**
     * A valid access token for the connected business, refreshing it first if
     * it's expired or close to it. Sage issues a new refresh token on every
     * refresh, so the new one must be saved or the connection is lost. A
     * refresh token also dies after 31 days unused.
     *
     * @throws \Exception If Sage has never been connected
     */
    private function ensureValidAccessToken(): array
    {
        $connection = $this->getConnection();
        $notConnected = $connection === null;
        if ($notConnected) throw new \Exception('Sage is not connected');

        $expiresAt = \strtotime($connection['access_token_expires_at']);
        $expiringSoon = $expiresAt - \time() <= self::TOKEN_REFRESH_MARGIN_SECONDS;

        if (!$expiringSoon) {
            return ['access_token' => $connection['access_token'], 'business_id' => $connection['business_id']];
        }

        $tokens = $this->requestToken([
            'grant_type' => 'refresh_token',
            'refresh_token' => $connection['refresh_token'],
        ]);

        $this->saveConnection(
            businessId: $connection['business_id'],
            businessName: $connection['business_name'],
            accessToken: $tokens['access_token'],
            refreshToken: $tokens['refresh_token'],
            expiresIn: (int) $tokens['expires_in'],
        );

        return ['access_token' => $tokens['access_token'], 'business_id' => $connection['business_id']];
    }

    /**
     * The connection is single-business, so refreshing just replaces the one row.
     */
    private function saveConnection(
        string $businessId,
        string $businessName,
        string $accessToken,
        string $refreshToken,
        int $expiresIn,
    ): void {
        $expiresAt = \date('Y-m-d H:i:s', \time() + $expiresIn);

        $this->disconnect();

        $sql = "INSERT INTO {$this->tablePrefix}sage_connection "
            . "(business_id, business_name, access_token, refresh_token, access_token_expires_at) "
            . "VALUES (:business_id, :business_name, :access_token, :refresh_token, :expires_at)";

        $this->database->query($sql);
        $this->database->bind(param: ':business_id', value: $businessId);
        $this->database->bind(param: ':business_name', value: $businessName);
        $this->database->bind(param: ':access_token', value: $accessToken);
        $this->database->bind(param: ':refresh_token', value: $refreshToken);
        $this->database->bind(param: ':expires_at', value: $expiresAt);
        $this->database->execute();
    }

    /**
     * Exchange a code or refresh token for a new access/refresh token pair.
     * Sage takes the client credentials in the form body, not a Basic header.
     */
    private function requestToken(array $parameters): array
    {
        $parameters['client_id'] = $this->clientId;
        $parameters['client_secret'] = $this->clientSecret;

        $ch = \curl_init(self::TOKEN_URL);
        \curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => \http_build_query($parameters),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
        ]);

        $response = \curl_exec($ch);
        $curlError = \curl_error($ch);

        if ($curlError) throw new \Exception("Sage token request curl error: {$curlError}");

        $decoded = \json_decode(json: (string) $response, associative: true);

        $hasError = !\is_array($decoded) || isset($decoded['error']) || !isset($decoded['access_token']);
        if ($hasError) {
            $description = \is_array($decoded) ? ($decoded['error_description'] ?? $decoded['error'] ?? 'unexpected response') : 'invalid response';
            throw new \Exception("Sage token request failed: {$description}");
        }

        return $decoded;
    }

    // ----------------------------------------
    // Accounting API
    // ----------------------------------------

    /**
     * Sales ledger accounts, for the settings dropdown.
     *
     * @return array [['id', 'name'], ...]
     */
    public function listSalesLedgerAccounts(): array
    {
        $response = $this->callApi(method: 'GET', path: 'ledger_accounts?visible_in=sales&items_per_page=200');

        return \array_map(static fn(array $item): array => [
            'id' => (string) $item['id'],
            'name' => (string) ($item['displayed_as'] ?? ''),
        ], $response['$items'] ?? []);
    }

    /**
     * Tax rates, for the settings dropdown and for working out each line's tax.
     *
     * @return array [['id', 'name', 'percentage'], ...]
     */
    public function listTaxRates(): array
    {
        $response = $this->callApi(method: 'GET', path: 'tax_rates?attributes=name,percentage&items_per_page=200');

        return \array_map(static fn(array $rate): array => [
            'id' => (string) $rate['id'],
            'name' => (string) ($rate['name'] ?? $rate['displayed_as'] ?? ''),
            'percentage' => (float) ($rate['percentage'] ?? 0),
        ], $response['$items'] ?? []);
    }

    /**
     * Find a customer by email, creating one if none exists.
     *
     * @return string The Sage contact id
     */
    public function findOrCreateCustomer(string $name, string $email): string
    {
        $query = \http_build_query(['contact_type_id' => 'CUSTOMER', 'email' => $email]);
        $existing = $this->callApi(method: 'GET', path: "contacts?{$query}");

        $found = !empty($existing['$items']);
        if ($found) return (string) $existing['$items'][0]['id'];

        $created = $this->callApi(method: 'POST', path: 'contacts', body: [
            'contact' => [
                'contact_type_ids' => ['CUSTOMER'],
                'name' => \mb_substr(\trim($name) ?: $email, 0, 200),
                'email' => $email,
            ],
        ]);

        return (string) $created['id'];
    }

    /**
     * Create a sales invoice for a customer. It is created as UNPAID (posted),
     * not as a draft.
     *
     * @param array $lineItems Each item: ['description', 'quantity', 'unitAmount']
     * @return array ['invoiceId', 'invoiceNumber']
     */
    public function createInvoice(
        string $customerId,
        array $lineItems,
        string $ledgerAccountId,
        string $taxRateId,
        float $taxPercentage,
        string $reference,
        string $invoiceDate,
    ): array {
        // Amounts go in as strings, and Sage needs us to supply each line's tax
        $invoiceLines = \array_map(static function (array $item) use ($ledgerAccountId, $taxRateId, $taxPercentage): array {
            $netAmount = \round($item['quantity'] * $item['unitAmount'], 2);
            $taxAmount = \round($netAmount * $taxPercentage / 100, 2);

            return [
                'description' => $item['description'],
                'ledger_account_id' => $ledgerAccountId,
                'quantity' => (string) $item['quantity'],
                'unit_price' => \number_format($item['unitAmount'], 2, '.', ''),
                'tax_rate_id' => $taxRateId,
                'tax_amount' => \number_format($taxAmount, 2, '.', ''),
            ];
        }, $lineItems);

        // No invoice_number: Sage auto-numbers, and a number of our own can leave gaps
        $response = $this->callApi(method: 'POST', path: 'sales_invoices', body: [
            'sales_invoice' => [
                'contact_id' => $customerId,
                'date' => $invoiceDate,
                'reference' => $reference,
                'invoice_lines' => $invoiceLines,
            ],
        ]);

        return [
            'invoiceId' => (string) $response['id'],
            'invoiceNumber' => $response['invoice_number'] ?? null,
        ];
    }

    /**
     * Confirm the connection still works by fetching the user's businesses.
     */
    public function testConnection(): array
    {
        try {
            $connection = $this->getConnection();
            $notConnected = $connection === null;
            if ($notConnected) throw new \Exception('Sage is not connected');

            $this->callApi(method: 'GET', path: 'businesses');

            return [
                'success' => true,
                'message' => 'Connection successful',
                'business' => $connection['business_name'],
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Make an authenticated call to the Sage Accounting API, refreshing
     * the access token first if it's about to expire.
     *
     * @throws \Exception On curl failure, malformed JSON, or an API error
     */
    private function callApi(string $method, string $path, ?array $body = null): array
    {
        $auth = $this->ensureValidAccessToken();

        return $this->request(
            method: $method,
            path: $path,
            accessToken: $auth['access_token'],
            businessId: $auth['business_id'],
            body: $body,
        );
    }

    private function request(
        string $method,
        string $path,
        string $accessToken,
        ?string $businessId = null,
        ?array $body = null,
    ): array {
        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/json',
        ];

        $hasBusiness = $businessId !== null;
        if ($hasBusiness) $headers[] = 'X-Business: ' . $businessId;

        $options = [
            CURLOPT_URL => self::API_URL . '/' . $path,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
        ];

        $hasBody = $body !== null;
        if ($hasBody) {
            $options[CURLOPT_POSTFIELDS] = \json_encode($body, JSON_THROW_ON_ERROR);
            $headers[] = 'Content-Type: application/json';
        }

        $options[CURLOPT_HTTPHEADER] = $headers;

        $ch = \curl_init();
        \curl_setopt_array($ch, $options);

        $response = \curl_exec($ch);
        $httpCode = \curl_getinfo(handle: $ch, option: CURLINFO_HTTP_CODE);
        $curlError = \curl_error($ch);

        if ($curlError) throw new \Exception("Sage API curl error: {$curlError}");

        $decoded = \json_decode(json: (string) $response, associative: true);

        $jsonDecodeError = \json_last_error() !== JSON_ERROR_NONE || !\is_array($decoded);
        if ($jsonDecodeError) throw new \Exception("Sage API returned invalid JSON (HTTP {$httpCode}): {$response}");

        $isError = $httpCode >= 400;
        if ($isError) {
            $message = $this->extractErrorMessage($decoded) ?? "HTTP {$httpCode}";
            throw new \Exception("Sage API error: {$message}");
        }

        return $decoded;
    }

    /**
     * Sage reports failures as a list of objects with $severity, $dataCode,
     * $message and $source.
     */
    private function extractErrorMessage(array $decoded): ?string
    {
        $errors = \array_is_list($decoded) ? $decoded : [];

        $messages = \array_map(
            static fn($error): string => \is_array($error) ? \trim(($error['$message'] ?? '') . ' ' . ($error['$source'] ?? '')) : '',
            $errors,
        );

        $messages = \array_filter($messages);

        return empty($messages) ? null : \implode('; ', $messages);
    }
}
