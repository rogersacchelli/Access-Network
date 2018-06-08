from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import *
from pysnmp.proto import rfc1902
import smtplib
import base64
import string
import random
import sys

def snmp_get(host, community, oid, cmdGen, logging, log_level):

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((host, 161)), *oid, lookupNames=False
    )

    if errorIndication:
        logging.info(
            'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + host + ' ' + str(errorIndication)))
        return -1
    elif errorStatus:
        logging.info(
            'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + errorStatus.prettyPrint() + ' ' +
                              errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        return -1
    else:
        return varBinds

def snmp_walk(host,community, oid, logging, log_level):
    # List of targets in the following format:
    # ( ( authData, transportTarget, varNames ), ... )
    list = []

    targets = (
        # 2-nd target (SNMPv2c over IPv4/UDP)
        (cmdgen.CommunityData(community),
         cmdgen.UdpTransportTarget((host, 161)),
         (oid,))
        ,
        # N-th target
        # ...
    )

    # Wait for responses or errors, submit GETNEXT requests for further OIDs
    def cbFun(sendRequestHandle, errorIndication, errorStatus, errorIndex,
              varBindTable, cbCtx):
        (varBindHead, authData, transportTarget) = cbCtx
        #print('%s via %s' % (authData, transportTarget))
        if errorIndication:
            logging.info(
                'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + host + ' ' + errorIndication))
            list.append('NaN')
            return -1
        if errorStatus:
            logging.info(
                'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + host + ' ' + errorStatus))
            list.append('NaN')
            return -1
        varBindTableRow = varBindTable[-1]
        for idx in range(len(varBindTableRow)):
            name, val = varBindTableRow[idx]
            if val is not None and varBindHead[idx] == name[0:len(varBindHead[idx])]:
                # still in table
                break
        else:
            #if 'DEBUG' in log_level:
            #    logging.debug(
            #        'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + host + ' went out of table ' + name))
            #    list.append('NaN')
            return

        for varBindRow in varBindTable:
            for oid, val in varBindRow:
                if val is None:
                    print(oid.prettyPrint())
                else:
                    #print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
                    list.append(val.prettyPrint())

        return True # continue table retrieval

    cmdGen = cmdgen.AsynCommandGenerator()

    # Submit initial GETNEXT requests and wait for responses
    for authData, transportTarget, varNames in targets:
        varBindHead = [x[0] for x in cmdGen.makeReadVarBinds(varNames)]
        cmdGen.nextCmd(
            authData, transportTarget, varNames,
            # User-space callback function and its context
            (cbFun, (varBindHead, authData, transportTarget)),
            lookupNames=True, lookupValues=True
        )

    cmdGen.snmpEngine.transportDispatcher.runDispatcher()

    return list

def snmp_getnext(host,community,oid,logging,log_level):

    list = []

    cmdGen = cmdgen.CommandGenerator()

    errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((host, 161)),
        cmdgen.ObjectIdentifier(oid),
        ignoreNonIncreasingOid=True, maxRows=1
    )
    if errorIndication:
        if 'DEBUG' in log_level:
            logging.debug(
                'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + host + ' went out of table ' ))
        list.append('NaN')
        return -1
    else:
        if errorStatus:
            if 'DEBUG' in log_level:
                logging.debug(
                    'EXCETION: %s' % (sys._getframe().f_code.co_name + ' ' + host + ' went out of table ' + errorStatus.prettyPrint()))
            list.append('NaN')
            return -1
        else:
            for varBindTableRow in varBindTable:
                for name, val in varBindTableRow:
                    list.append(name.prettyPrint())

    return list