<?php

/*
 * This file is part of SeAT
 *
 * Copyright (C) 2015 to 2020 Leon Jacobs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

namespace EVEployment\Socialite\EVEOnline;

use EVEployment\Socialite\EVEOnline\Checker\Claim\AzpChecker;
use EVEployment\Socialite\EVEOnline\Checker\Claim\NameChecker;
use EVEployment\Socialite\EVEOnline\Checker\Claim\OwnerChecker;
use EVEployment\Socialite\EVEOnline\Checker\Claim\ScpChecker;
use EVEployment\Socialite\EVEOnline\Checker\Claim\SubEVECharacterChecker;
use EVEployment\Socialite\EVEOnline\Checker\Header\TypeChecker;
use Jose\Component\Core\JWKSet;
use Jose\Easy\Load;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Providerv2 extends AbstractProvider {
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'EVEONLINE-v2';

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * @return array
     */
    public static function additionalConfigKeys() {
        return [
            'endpoint',
        ];
    }


    /**
     * Get the authentication URL for the provider.
     *
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state) {
        return $this->buildAuthUrlFromBase($this->getOAuthConfig()->authorization_endpoint, $state);
    }

    /**
     * Get the token URL for the provider.
     *
     * @return string
     */
    protected function getTokenUrl() {
        return $this->getOAuthConfig()->token_endpoint;
    }

    /**
     * Get the raw user for the given access token.
     *
     * @param string $token
     * @return array
     */
    protected function getUserByToken($token) {
        $scopes = $this->getScopes();

        // pulling JWK sets from CCP
        $jwk_sets = $this->getJwkSets();

        // attempt to parse the JWT and collect payload
        $jws = Load::jws($token)
            ->algs(['RS256', 'ES256', 'HS256'])
            ->exp()
            ->iss($this->getOAuthConfig()->issuer)
            ->header('typ', new TypeChecker(['JWT'], true))
            ->claim('scp', new ScpChecker($scopes))
            ->claim('sub', new SubEVECharacterChecker())
            ->claim('azp', new AzpChecker($this->getConfig('client_id')))
            ->claim('name', new NameChecker())
            ->claim('owner', new OwnerChecker())
            ->keyset($jwk_sets)
            ->run();

        return $jws->claims->all();
    }

    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param array $user
     * @return \Laravel\Socialite\Two\User
     */
    protected function mapUserToObject(array $user) {
        $character_id = strtr($user['sub'], ['CHARACTER:EVE:' => '']);

        return (new User)->setRaw($user)->map([
            'id'                   => $character_id,
            'name'                 => $user['name'],
            'nickname'             => $user['name'],
            'character_owner_hash' => $user['owner'],
            'scopes'               => is_array($user['scp']) ? $user['scp'] : [$user['scp']],
            'expires_on'           => $user['exp'],
        ]);
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param  string $code
     *
     * @return array
     */
    protected function getTokenFields($code) {
        return array_merge(parent::getTokenFields($code), ['grant_type' => 'authorization_code']);
    }

    /**
     * @return string Endpoint
     */
    protected function getEndpoint() {
        return $this->getConfig('endpoint', 'https://login.eveonline.com');
    }

    /**
     * @return object OAuth Metadata
     */
    protected function getOAuthConfig() {
        static $data = null;

        if ($data === null) {
            $configUrl = $this->getConfig() . '/.well-known/oauth-authorization-server';

            $response = $this->getHttpClient()->get($configUrl);

            $data = json_decode($response->getBody()->getContents());
        }

        return $data;
    }

    /**
     * @return string
     */
    private function getJwkUri(): string {
        $metadata = $this->getOAuthConfig();

        return $metadata->jwks_uri;
    }

    /**
     * @return array An array representing the JWK Key Sets
     */
    private function getJwkSets(): JWKSet {
        $jwk_uri = $this->getJwkUri();

        $response = $this->getHttpClient()->get($jwk_uri);

        return JWKSet::createFromJson($response->getBody());
    }
}
