'use strict';

const ldap = require('ldapjs');

const ldapBindScheme = 'ldap://';
const ldapBindFqdn = 'corp.contoso.com';
const ldapBindPort = '389';
const ldapBindDn = 'CN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=contoso,DC=com';
const ldapBindPwd = 'COMPLEX_PASSWORD_STRING';
const ldapUserDn = 'CN=John S.,OU=User Accounts,DC=corp,DC=contoso,DC=com';
const ldapUserAttr = 'extensionAttribute2';
const ldapUserSecret = 'BASE64_STRING';

let ldapModifyRec = (hosts, ldap_change, i) => {
    return new Promise((resolve, reject) => {
        const ldap_bind_url = ldapBindScheme + hosts[i] + ':' + ldapBindPort;
        const ldap_client = ldap.createClient({url: ldap_bind_url, tlsOptions: {'rejectUnauthorized': false}});

        ldap_client.on('error', (error) => {
            // LDAP bind failed
            return reject('LDAP bind error: ' + error);
        });

        ldap_client.bind(ldapBindDn, ldapBindPwd, (error) => {
            if (error) {
                // LDAP bind failed
                return reject('LDAP bind error: ' + error);
            } else {
                console.log('LDAP bind success ' + ldap_bind_url);
                try {
                    ldap_client.modify(ldapUserDn, ldap_change, (error) => {
                        ldap_client.unbind((error) => {
                            if (error) {
                                // LDAP unbind failed
                                console.error('LDAP unbind error: ' + error);
                            }
                        });
                        if (error) {
                            // LDAP modify failed
                            return reject('LDAP modify error: ' + error);
                        } else {
                            // LDAP modify successful
                            return resolve();
                        }
                    });
                } catch (error) {
                    // LDAP modify failed
                    return reject('LDAP modify error: ' + error);
                }
            }
        });
    });
};

let modifyNext = (records, ldap_change, i) => {
    ldapModifyRec(records, ldap_change, i).then(() => {
        console.log('LDAP modify success');
    }).catch((error) => {
        console.error('ldapModifyRec error: ' + error);

        if (records.length - 1 === i) {
            // LDAP server list reached its end
            console.error('None of LDAP servers returned success');
        } else {
            modifyNext(records, ldap_change, ++i);
        }
    });
};

dns.resolve(ldapBindFqdn, (error, records) => {
    if (error) {
        // DNS resolve failed
        console.error('DNS resolve error: ' + error);
    } else {
        console.log('DNS resolve success: ' + records);
        const ldap_modification = {};
        ldap_modification[ldapUserAttr] = ldapUserSecret;
        const ldap_change = new ldap.Change({operation: 'replace', modification: ldap_modification});
        modifyNext(records, ldap_change, 0);
    }
});
