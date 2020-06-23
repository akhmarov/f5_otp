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

let ldapModifyRec = (hosts, ldapChange, i) => {
    return new Promise((resolve, reject) => {
        const ldapBindUrl = ldapBindScheme + hosts[i] + ':' + ldapBindPort;
        const ldapClient = ldap.createClient({url: ldapBindUrl, tlsOptions: {'rejectUnauthorized': false}});

        ldapClient.on('error', (error) => {
            // LDAP bind failed
            return reject('LDAP bind error: ' + error);
        });

        ldapClient.bind(ldapBindDn, ldapBindPwd, (error) => {
            if (error) {
                // LDAP bind failed
                return reject('LDAP bind error: ' + error);
            } else {
                console.log('LDAP bind success ' + ldapBindUrl);
                try {
                    ldapClient.modify(ldapUserDn, ldapChange, (error) => {
                        ldapClient.unbind((error) => {
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

let modifyNext = (records, ldapChange, i) => {
    ldapModifyRec(records, ldapChange, i).then(() => {
        console.log('LDAP modify success');
    }).catch((error) => {
        console.error('ldapModifyRec error: ' + error);

        if (records.length - 1 === i) {
            // LDAP server list reached its end
            console.error('None of LDAP servers returned success');
        } else {
            modifyNext(records, ldapChange, ++i);
        }
    });
};

dns.resolve(ldapBindFqdn, (error, records) => {
    if (error) {
        // DNS resolve failed
        console.error('DNS resolve error: ' + error);
    } else {
        console.log('DNS resolve success: ' + records);
        const ldapModification = {};
        ldapModification[ldapUserAttr] = ldapUserSecret;
        const ldapChange = new ldap.Change({operation: 'replace', modification: ldapModification});
        modifyNext(records, ldapChange, 0);
    }
});
