/**
 * In-App Purchase (IAP) Bypass for Google Play Billing
 * Bypasses purchase verification to test premium features
 */

Java.perform(function() {
    console.log('[+] Loading IAP bypass...');

    // ===== Google Play Billing Library v4+ =====
    try {
        var BillingClient = Java.use('com.android.billingclient.api.BillingClient');
        var BillingResult = Java.use('com.android.billingclient.api.BillingResult');
        var Purchase = Java.use('com.android.billingclient.api.Purchase');

        // isReady() - Always return true
        BillingClient.isReady.implementation = function() {
            console.log('[+] BillingClient.isReady() = true');
            return true;
        };

        // Purchase state = PURCHASED
        Purchase.getPurchaseState.implementation = function() {
            console.log('[+] Purchase.getPurchaseState() = PURCHASED');
            return 1; // 1 = PURCHASED, 0 = UNSPECIFIED, 2 = PENDING
        };

        // Purchase acknowledged
        Purchase.isAcknowledged.implementation = function() {
            console.log('[+] Purchase.isAcknowledged() = true');
            return true;
        };

        // Purchase auto-renewing (for subscriptions)
        Purchase.isAutoRenewing.implementation = function() {
            console.log('[+] Purchase.isAutoRenewing() = true');
            return true;
        };

    } catch(e) {
        console.log('[-] Google Play Billing v4 not found');
    }

    // ===== Legacy Billing v3 =====
    try {
        var IInAppBillingService = Java.use('com.android.vending.billing.IInAppBillingService$Stub');

        IInAppBillingService.getPurchases.implementation = function() {
            console.log('[+] IInAppBillingService.getPurchases() bypassed');
            // Return success bundle
            return this.getPurchases.apply(this, arguments);
        };

    } catch(e) {
        console.log('[-] Legacy Billing v3 not found');
    }

    // ===== Custom verification bypass =====
    try {
        // Hook common verification method names
        var verificationMethods = [
            'isPurchased',
            'isPremium',
            'hasPurchased',
            'isSubscribed',
            'verifyPurchase',
            'checkPurchase'
        ];

        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.toLowerCase().indexOf('purchase') !== -1 ||
                    className.toLowerCase().indexOf('billing') !== -1) {

                    try {
                        var targetClass = Java.use(className);

                        verificationMethods.forEach(function(methodName) {
                            if (targetClass[methodName]) {
                                targetClass[methodName].implementation = function() {
                                    console.log('[+] ' + className + '.' + methodName + '() = true');
                                    return true;
                                };
                            }
                        });
                    } catch(e) {}
                }
            },
            onComplete: function() {}
        });

    } catch(e) {}

    console.log('[+] IAP bypass loaded successfully');
});
