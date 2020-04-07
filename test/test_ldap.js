'use strict';

const ldap = require('ldapjs');

const ldap_bind_scheme = 'ldap://';
const ldap_bind_fqdn = 'corp.contoso.com';
const ldap_bind_port = '389';
const ldap_bind_dn = 'CN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=contoso,DC=com';
const ldap_bind_pwd = 'COMPLEX_PASSWORD_STRING';
const ldap_user_dn = 'CN=John S.,OU=User Accounts,DC=corp,DC=contoso,DC=com';
const ldap_user_attr = 'extensionAttribute2';
const ldap_user_secret = 'BASE64_STRING';

let ldapModifyRec = (hosts, ldap_change, i) => {
    return new Promise((resolve, reject) => {
        const ldap_bind_url = ldap_bind_scheme + hosts[i] + ':' + ldap_bind_port;
        const ldap_client = ldap.createClient({url: ldap_bind_url, tlsOptions: {'rejectUnauthorized': false}});

        ldap_client.on('error', (error) => {
            // LDAP bind failed
            return reject('LDAP bind error: ' + error);
        });

        ldap_client.bind(ldap_bind_dn, ldap_bind_pwd, (error) => {
            if (error) {
                // LDAP bind failed
                return reject('LDAP bind error: ' + error);
            } else {
                console.log('LDAP bind success ' + ldap_bind_url);
                try {
                    ldap_client.modify(ldap_user_dn, ldap_change, (error) => {
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

dns.resolve(ldap_bind_fqdn, (error, records) => {
    if (error) {
        // DNS resolve failed
        console.error('DNS resolve error: ' + error);
    } else {
        console.log('DNS resolve success: ' + records);
        const ldap_modification = {};
        ldap_modification[ldap_user_attr] = ldap_user_secret;
        const ldap_change = new ldap.Change({operation: 'replace', modification: ldap_modification});
        modifyNext(records, ldap_change, 0);
    }
});
