//
// Name:     APM-LDAP-Modify_ilx
// Date:     October 2019
// Version:  2.0
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
const ldap_modify_debug = 0;

const f5 = require('f5-nodejs');
const ldap = require('ldapjs');
const dns = require('dns');

const ilx = new f5.ILXServer();
const logger = new f5.ILXLogger();

ilx.addMethod('ldap_modify', (req, res) => {
    const ldap_bind_scheme = req.params()[0];
    const ldap_bind_fqdn = req.params()[1];
    const ldap_bind_port = req.params()[2];
    const ldap_bind_dn = req.params()[3];
    const ldap_bind_pwd = req.params()[4];
    const ldap_user_dn = req.params()[5];
    const ldap_user_attr = req.params()[6];
    const ldap_user_secret = req.params()[7];

    if (ldap_modify_debug) {
        logger.send('ldap_bind_scheme = ' + ldap_bind_scheme + ', ldap_bind_fqdn = ' + ldap_bind_fqdn + ', ldap_bind_port = ' + ldap_bind_port);
        logger.send('ldap_bind_dn = ' + ldap_bind_dn + ', ldap_bind_pwd = *');
        logger.send('ldap_user_dn = ' + ldap_user_dn + ', ldap_user_attr = ' + ldap_user_attr + ', ldap_user_secret = ' + ldap_user_secret);
    }

    if (!ldap_bind_scheme || ldap_bind_scheme.trim().length === 0 || !ldap_bind_fqdn || ldap_bind_fqdn.trim().length === 0
        || !ldap_bind_port || ldap_bind_port.trim().length === 0 || !ldap_bind_dn || ldap_bind_dn.trim().length === 0
        || !ldap_bind_pwd || ldap_bind_pwd.trim().length === 0 || !ldap_user_dn || ldap_user_dn.trim().length === 0
        || !ldap_user_attr || ldap_user_attr.trim().length === 0 || !ldap_user_secret || ldap_user_secret.trim().length === 0)
    {
        // Invalid input data from iRule
        logger.send('Invalid input data from iRule');
        res.reply(3);
        return;
    }

    var ldapModifyRec = (hosts, ldap_change, i) => {
        return new Promise((resolve, reject) => {
            var ldap_bind_url = ldap_bind_scheme + hosts[i] + ':' + ldap_bind_port;
            var ldap_client = ldap.createClient({url: ldap_bind_url, tlsOptions: {'rejectUnauthorized': false}});

            ldap_client.on('error', (error) => {
                // LDAP bind failed
                return reject('LDAP bind error: ' + error);
            });

            ldap_client.bind(ldap_bind_dn, ldap_bind_pwd, (error) => {
                if (error) {
                    // LDAP bind failed
                    return reject('LDAP bind error: ' + error);
                } else {
                    if (ldap_modify_debug) {
                        logger.send('LDAP bind success ' + ldap_bind_url);
                    }
                    try {
                        ldap_client.modify(ldap_user_dn, ldap_change, (error) => {
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
            if (ldap_modify_debug) {
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

    dns.resolve(ldap_bind_fqdn, (error, records) => {
        if (error) {
            // DNS resolve failed
            logger.send('DNS resolve error: ' + error);
            res.reply(7);
            return;
        } else {
            const ldap_modification = {};
            ldap_modification[ldap_user_attr] = ldap_user_secret;
            const ldap_change = new ldap.Change({operation: 'replace', modification: ldap_modification});

            if (ldap_modify_debug) {
                logger.send('DNS resolve success: ' + records);
            }

            modifyNext(records, ldap_change, 0);
        }
    });
});

ilx.listen();
