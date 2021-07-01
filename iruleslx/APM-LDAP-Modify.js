//
// Name:     APM-LDAP-Modify_ilx
// Date:     June 2021
// Version:  2.7
//
// Authors:
//   Brett Smith
//   Vladimir Akhmarov
//
// Description:
//  This iRule LX receives LDAP bind data and LDAP modify data from classic
//  iRule. After successful LDAP or LDAPS connection it modifies selected LDAP
//  attribute with new value. This iRule LX assumes that LDAP URL will use
//  ldap:// or ldaps:// scheme. By default bind operation has special parameter
//  rejectUnauthorized=false (may be changed using variable flagVerify) to allow
//  connections to untrusted SSL servers. This iRule LX assumes that selected
//  LDAP attribute is already present on LDAP user. Otherwise modify operation
//  will fail
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
//  3 - Distinguished name of a LDAP administrator with selected attribute
//      modification permissions
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
//  7 - DNS configuration failed
//  8 - DNS resolve failed
//

'use strict';

// Debug switch
const flagDebug = 0;

// Certitificate verification switch
const flagVerify = false;

const f5 = require('f5-nodejs');
const dns = require('dns');
const ldap = require('ldapjs');

const ilx = new f5.ILXServer();
const logger = new f5.ILXLogger();

//
// ILX helper: apm_decode
//
// Description:
//  This function decodes HEX encoded string that may be stored in APM session
//  variable if it contains non-ASCII characters. For more info see description
//  of resolved BugID 399693 under BIG-IP APM 12.0.0 Release Notes
//

function apm_decode(str = '') {
    if (str.slice(0, 2) == '0x') {
        // Return decoded UTF-8 string
        return Buffer.from(str.slice(2), 'hex').toString('utf8');
    } else {
        // Return string as is
        return str;
    }
}

//
// ILX method: ldap_modify
//
// Description:
//  This function is used to modify selected attribute for specified LDAP user.
//  LDAP servers discovered using DNS so ADDS domain or LDAP FQDN must be used.
//

ilx.addMethod('ldap_modify', (req, res) => {
    const ldapBindScheme = req.params()[0];
    const ldapBindFqdn = req.params()[1];
    const ldapBindPort = req.params()[2];
    const ldapBindDn = req.params()[3];
    const ldapBindPwd = req.params()[4];
    const ldapUserDn = apm_decode(req.params()[5]);
    const ldapUserAttr = req.params()[6];
    const ldapUserSecret = req.params()[7];
    const ldapNameResolver = req.params()[8];

    if (flagDebug) {
        logger.send('ldapBindScheme = ' + ldapBindScheme + ', ldapBindFqdn = ' + ldapBindFqdn + ', ldapBindPort = ' + ldapBindPort + ', ldapBindDn = ' + ldapBindDn + ', ldapBindPwd = *, ldapUserDn = ' + ldapUserDn + ', ldapUserAttr = ' + ldapUserAttr + ', ldapUserSecret = ' + ldapUserSecret + ', ldapNameResolver = ' + ldapNameResolver);
    }

    if (!ldapBindScheme || ldapBindScheme.trim().length === 0 || !ldapBindFqdn || ldapBindFqdn.trim().length === 0
        || !ldapBindPort || ldapBindPort.trim().length === 0 || !ldapBindDn || ldapBindDn.trim().length === 0
        || !ldapBindPwd || ldapBindPwd.trim().length === 0 || !ldapUserDn || ldapUserDn.trim().length === 0
        || !ldapUserAttr || ldapUserAttr.trim().length === 0 || !ldapUserSecret || ldapUserSecret.trim().length === 0
        || !ldapNameResolver || ldapNameResolver.trim().length === 0)
    {
        // Invalid input data from iRule
        logger.send('Invalid input data from iRule');
        res.reply(3);
        return;
    }

    var ldapModifyRec = (hosts, ldapChange, i) => {
        return new Promise((resolve, reject) => {
            var ldapBindUrl = ldapBindScheme + hosts[i] + ':' + ldapBindPort;
            var ldapClient = ldap.createClient({url: ldapBindUrl, tlsOptions: {rejectUnauthorized: flagVerify}});

            ldapClient.on('error', (error) => {
                // LDAP bind failed
                return reject('LDAP bind error: ' + error);
            });

            ldapClient.bind(ldapBindDn, ldapBindPwd, (error) => {
                if (error) {
                    // LDAP bind failed
                    return reject('LDAP bind error: ' + error);
                } else {
                    if (flagDebug) {
                        logger.send('LDAP bind success ' + ldapBindUrl);
                    }
                    try {
                        ldapClient.modify(ldapUserDn, ldapChange, (error) => {
                            ldapClient.unbind((error) => {
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

    var modifyNext = (records, ldapChange, i) => {
        ldapModifyRec(records, ldapChange, i).then(() => {
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
                modifyNext(records, ldapChange, ++i);
            }
        });
    };

    try {
        // Configure new DNS resolvers
        dns.setServers(ldapNameResolver.split('|'));
    } catch (error) {
        logger.send('DNS config error: ' + error);
        res.reply(7);
        return;
    }

    dns.resolve(ldapBindFqdn, (error, records) => {
        if (error) {
            // DNS resolve failed
            logger.send('DNS resolve error: ' + error);
            res.reply(8);
            return;
        } else {
            const ldapModification = {};
            ldapModification[ldapUserAttr] = ldapUserSecret;
            const ldapChange = new ldap.Change({operation: 'replace', modification: ldapModification});

            if (flagDebug) {
                logger.send('DNS resolve success: ' + records);
            }

            modifyNext(records, ldapChange, 0);
        }
    });
});

ilx.listen();
