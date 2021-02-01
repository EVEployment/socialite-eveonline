<?php

namespace EVEployment\Socialite\EVEOnline;

use SocialiteProviders\Manager\SocialiteWasCalled;

class EVEOnlineExtendSocialite {
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled) {
        $socialiteWasCalled->extendSocialite('eveonline-v2', Providerv2::class);
    }
}
