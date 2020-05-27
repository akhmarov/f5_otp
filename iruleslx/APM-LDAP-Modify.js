//
// Name:     APM-LDAP-Modify_ilx
// Date:     May 2020
// Version:  2.3
//
// Authors:
//   Brett Smith
//   Vladimir Akhmarov
//
// Description:
//  This iRule LX receives LDAP bind data and LDAP modify data from classic
//  iRule. After successful LDAPS connection it modifies selected LDAP attribute
//  with new value. This iRule LX assumes that LDAP URL will use ldaps:// scheme
//  and 636 port. Bind operation has special parameter rejectUnauthorized=false
//  to allow connection to untrusted SSL servers. This iRule LX assumes that
//  selected LDAP attribute is already present on LDAP user. Otherwise modify
//  operation will fail
//
// Note:
//  To disable sdmd log throttling (enabled by default) use command:
//  tmsh modify sys db log.sdmd.level value debug
//  To enable sdmd log throttling (default behaviour) use command:
//  tmsh modify sys db log.sdmd.level value info
//
// Arguments:
//  0 - LDAP scheme (ldap:// or ldaps://)
//  1 - LDAP fully qualified domain name or hostname
//  2 - LDAP port (389 or 636)
//  3 - Distinguished name of a LDAP administrator with selected attribute modification permissions
//  4 - Password of a LDAP administrator
//  5 - Distinguished name of a LDAP user to update
//  6 - Selected LDAP attribute name to update
//  7 - New LDAP attribute value
//
// Return Codes:
//  0 - LDAP modify successful
//  3 - Invalid input data from iRule
//  4 - LDAP bind failed
//  5 - LDAP modify failed
//  6 - LDAP server list reached its end
//  7 - DNS resolve failed
//

'use strict';

// Debug switch
const flagDebug = 0;

const f5 = require('f5-nodejs');
const ldap = require('ldapjs');
const dns = require('dns');

const ilx = new f5.ILXServer();
const logger = new f5.ILXLogger();

ilx.addMethod('ldap_modify', (req, res) => {
    const ldapBindScheme = req.params()[0];
    const ldapBindFqdn = req.params()[1];
    const ldapBindPort = req.params()[2];
    const ldapBindDn = req.params()[3];
    const ldapBindPwd = req.params()[4];
    const ldapUserDn = req.params()[5];
    const ldapUserAttr = req.params()[6];
    const ldapUserSecret = req.params()[7];

    if (flagDebug) {
        logger.send('ldapBindScheme = ' + ldapBindScheme + ', ldapBindFqdn = ' + ldapBindFqdn + ', ldapBindPort = ' + ldapBindPort + 'ldapBindDn = ' + ldapBindDn + ', ldapBindPwd = *, ldapUserDn = ' + ldapUserDn + ', ldapUserAttr = ' + ldapUserAttr + ', ldapUserSecret = ' + ldapUserSecret);
    }

    if (!ldapBindScheme || ldapBindScheme.trim().length === 0 || !ldapBindFqdn || ldapBindFqdn.trim().length === 0
        || !ldapBindPort || ldapBindPort.trim().length === 0 || !ldapBindDn || ldapBindDn.trim().length === 0
        || !ldapBindPwd || ldapBindPwd.trim().length === 0 || !ldapUserDn || ldapUserDn.trim().length === 0
        || !ldapUserAttr || ldapUserAttr.trim().length === 0 || !ldapUserSecret || ldapUserSecret.trim().length === 0)
    {
        // Invalid input data from iRule
        logger.send('Invalid input data from iRule');
        res.reply(3);
        return;
    }

    var ldapModifyRec = (hosts, ldap_change, i) => {
        return new Promise((resolve, reject) => {
            var ldap_bind_url = ldapBindScheme + hosts[i] + ':' + ldapBindPort;
            var ldap_client = ldap.createClient({url: ldap_bind_url, tlsOptions: {'rejectUnauthorized': false}});

            ldap_client.on('error', (error) => {
                // LDAP bind failed
                return reject('LDAP bind error: ' + error);
            });

            ldap_client.bind(ldapBindDn, ldapBindPwd, (error) => {
                if (error) {
                    // LDAP bind failed
                    return reject('LDAP bind error: ' + error);
                } else {
                    if (flagDebug) {
                        logger.send('LDAP bind success ' + ldap_bind_url);
                    }
                    try {
                        ldap_client.modify(ldapUserDn, ldap_change, (error) => {
                            ldap_client.unbind((error) => {
                                if (error) {
                                    // LDAP unbind failed
                                    logger.send('LDAP unbind error: ' + error);
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

    var modifyNext = (records, ldap_change, i) => {
        ldapModifyRec(records, ldap_change, i).then(() => {
            if (flagDebug) {
                logger.send('LDAP modify success');
            }
            res.reply(0);
            return;
        }).catch((error) => {
            logger.send('ldapModifyRec error: ' + error);

            if (records.length - 1 === i) {
                // LDAP server list reached its end
                logger.send('None of LDAP servers returned success');
                res.reply(6);
            } else {
                modifyNext(records, ldap_change, ++i);
            }
        });
    };

    dns.resolve(ldapBindFqdn, (error, records) => {
        if (error) {
            // DNS resolve failed
            logger.send('DNS resolve error: ' + error);
            res.reply(7);
            return;
        } else {
            const ldap_modification = {};
            ldap_modification[ldapUserAttr] = ldapUserSecret;
            const ldap_change = new ldap.Change({operation: 'replace', modification: ldap_modification});

            if (flagDebug) {
                logger.send('DNS resolve success: ' + records);
            }

            modifyNext(records, ldap_change, 0);
        }
    });
});

ilx.listen();
