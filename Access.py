#!/usr/bin/python

import telnetlib
import sys
import socket
import re
import paramiko
import os
from snmp_utils import snmp_get, snmp_walk, snmp_getnext
from time import sleep, time
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902
import time, datetime



class msanKeymile(object):
    'Class for KEYMILEs functions defines methods for getting MSAN information'

    def __init__(self, host, slot, port, logging, log_level):
        self.tn = None
        self.username = "manager"
        self.password = "\n"
        self.host = str(host)
        self.tn_port = 23
        self.timeout = 3
        self.login_prompt = b"login as: "
        self.password_prompt = b"password: "
        self.cmd_prompt = b"#"
        self.slot = slot
        self.port = port
        self.logging = logging
        self.log_level = log_level

    def connect(self):
        try:
            self.tn = telnetlib.Telnet(self.host, self.tn_port, self.timeout)
        except Exception as error:
            self.logging.debug(
                '%s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                   + ' ' + str(self.port)) + " | Error: " + str(error))
            return -1

        try:
            if self.tn.read_until(self.login_prompt, self.timeout) != self.login_prompt:
                self.logging.debug(
                    '%s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                       + ' ' + str(self.port)) + " | Error: Unmatched Prompt")
        except Exception as error:
            self.logging.debug(
                '%s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                        + ' ' + str(self.port)) + " | Error: " + str(error))

            return -1

        try:
            self.tn.write(self.username.encode('ascii') + b"\n")
        except Exception as error:
            self.logging.debug(
                '%s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                        + ' ' + str(self.port)) + " | Error: " + str(error))
            return -1

        if self.password:
            try:
                self.write(self.password)
                if not self.tn.read_until(self.password_prompt, self.timeout):
                    return -1
            except Exception as error:
                self.logging.debug(
                    '%s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                            + ' ' + str(self.port)) + " | Error: " + str(error))


    def write(self, msg):
      #self.tn.read_until(self.cmd_prompt, self.timeout)
      self.tn.write(msg.encode('ascii') + b'\n')
      #self.tn.write("# END".encode('ascii')+b'\n')
      return self.tn.read_until(self.cmd_prompt).decode('ascii')

    def read_until(self, value):
        try:
            return self.tn.read_until(value, self.timeout)
        except:
            return -1

    def read_all(self):
        try:
            return self.tn.read_all()
        except socket.timeout:
            print("read_all socket.timeout")
            return False

    def close(self):
        try:
            self.tn.write(b"exit\n")
        except:
            self.logging.warning(
                'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' fail exit ' + self.host))

        self.tn.close()
        return True

    def get_card_invetory(self):
        output = {}
        try:
            out = self.write('get /unit-' + (str(self.slot)) + '/main/HardwareAndSoftware')
            for line in out.splitlines():
                try:
                    match_hw = (re.search(r'"(.*)".*# Hardware$', line))
                    match_sw = (re.search(r'"(.*)".*# Software$', line))
                    if match_hw:
                        output.update({'BOARD_TYPE': match_hw.group(1)})
                    elif match_sw:
                        output.update({'BOARD_SW': match_sw.group(1)})
                except Exception as error:
                    self.logging.debug(
                        'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                            + " | Error: " + str(error)))
        except Exception as error:
            self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' '
                                                         + str(self.slot) + " | Error: " + str(error)))

        return output

    def get_admin_status(self):
       output = {}
       try:
           out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/main/AdministrativeStatus')
           for line in out.splitlines():
               try:
                   match = (re.search(r'(\w+)\s*\\ # State', line))
                   if match:
                       if match.group(1).encode('ascii') == "Up":
                           output.update({'ADMIN_STATE': '1'})
                       else:
                           output.update({'ADMIN_STATE': '0'})
               except Exception as error:
                   self.logging.debug(
                       'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                 + ' ' + str(self.port) + " | Error: " + str(error)))
       except Exception as error:
           self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                   + ' ' + str(self.port)) + " | Error: " + str(error))

       return output

    def get_oper_status(self):
       output = {}
       try:
           out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/main/OperationalStatus')
           for line in out.splitlines():
               try:
                   match = (re.search(r'([A-Z,a-z]+)\s*\\ # State', line))
                   if match:
                       output.update({'OPER_STATE': match.group(1)})
               except:
                   self.logging.debug(
                       'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                 + ' ' + str(self.port)))
       except:
           self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                 + ' ' + str(self.port)))

       return output

    def get_chan_status(self, card):
       output = {}

       # flags to detect which output is correct
       rate = False
       delay = False
       inp = False

       try:
           out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/chan-1/status/status')
           for line in out.splitlines():
            match_rate = (re.search(r"(\d+)\s*\\ # CurrentRate$", line))
            match_delay = (re.search(r"(\d+)\s*\\ # CurrentDelay$", line))
            match_inp = (re.search(r'(\w.+)\s*\\ # CurrentImpulse$', line))
            if match_rate is not None:
              if not rate:
                output.update({'LINE_RATE_DS': match_rate.group(1)})
                rate = True
              else:
                output.update({'LINE_RATE_US': match_rate.group(1)})
            elif match_delay is not None:
             if not delay:
                output.update({'CHAN_DELAY_DS': match_delay.group(1)})
                delay = True
             else:
                output.update({'CHAN_DELAY_US': match_delay.group(1)})
            elif match_inp is not None:
              if not inp:
                output.update({'CHAN_INP_DS':(format(float(
                    match_inp.group(1).split('E')[0])*10**int(match_inp.group(1).split('E')[1]),'.3g'))})
                inp = True
              else:
                output.update({'CHAN_INP_US':
                                   (format(float(match_inp.group(1).split('E')[0])*10**int(match_inp.group(1).split('E')[1]),'.3g'))})
       except:
           self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                   + ' ' + str(self.port)))

       return output

    def get_attainable_rate(self):
       output = {}
       try:
           out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/AttainableRate')
           for line in out.splitlines():
               try:
                   match_ds = (re.search(r'(\d+)\s*\\ # Downstream', line))
                   match_us = (re.search(r'(\d+)\s*\\ # Upstream', line))
                   if match_ds:
                       output.update({'SPECTRUM_MABR_DS': match_ds.group(1)})
                   elif match_us:
                       output.update({'SPECTRUM_MABR_US': match_us.group(1)})
               except:
                   self.logging.debug(
                       'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                          + ' ' + str(self.port)))
       except:
           self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                   + ' ' + str(self.port)))

       return output

    def get_vendorid(self):
        output = {}

        # flag to verifify output
        hw_model = False
        sw_model = False
        try:
           out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/vendorId')
           for line in out.splitlines():
               try:
                   match_ds_chip = (re.search(r'(".*").*# VendorId$', line))
                   match_ds_sw = (re.search(r'(".*").*# VersionNumber$', line))
                   match_us_chip = (re.search(r'(".*").*# VendorId$', line))
                   match_us_sw = (re.search(r'(".*").*# VersionNumber$', line))
                   if match_ds_chip and not hw_model:
                       output.update({'VENDOR_ID_CO_HW': match_ds_chip.group(1).replace('"','')})
                       hw_model = True
                   elif match_ds_sw and not sw_model:
                       output.update({'VENDOR_ID_CO_SW': match_ds_sw.group(1).replace('"','')})
                       sw_model = True
                   elif match_us_chip:
                       output.update({'VENDOR_ID_CPE_HW': match_us_chip.group(1).replace('"','')})
                   elif match_us_sw:
                       output.update({'VENDOR_ID_CPE_SW': match_us_sw.group(1).replace('"','')})
               except:
                   self.logging.debug(
                       'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                 + ' ' + str(self.port)))
        except:
            self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                   + ' ' + str(self.port)))

        return output

    def get_chan_prof(self, card):
        output = {}
        try:
            if (card[0:3] == "SUA"):
                out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/chan-1/cfgm/profilename')

            elif (card[0:3] == "SUV"):
                out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/chan-1/cfgm/chanprofile')

            for line in out.splitlines():
                match = (re.search(r'(\w+)\s*\\ # Name', line))
                if match:
                    output.update({'CHAN_PROF_NAME': match.group(1)})
        except:
            self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port)))

        return output

    def get_port_prof(self, card):
        output = {}
        try:
            if (card[0:3] == "SUA"):
                out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/cfgm/portprofile')
            elif (card[0:3] == "SUV"):
                out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/cfgm/portprofiles')

            enable = False # flag for enabled profile | if = 1 OK | if = 2
            enable_once = False
            for line in out.splitlines():
                if (card[0:6] == "SUVD11" or card[0:5] == "SUVD3"):
                    match_enable = (re.search(r'(\w+)\s*\\ # Enabled', line))
                    match_profile = (re.search(r'(\w+)\s*\\ # Name', line))
                    if match_enable:
                        if match_enable.group(1) == "true" and not enable_once:
                            enable = True
                            enable_once = True
                        elif match_enable.group(1) == "true" and enable_once:
                            output = {'SPECTRUM_PROF_NAME': "two_profiles_set"}
                            return output

                    if match_profile and enable:
                        output.update({'SPECTRUM_PROF_NAME': match_profile.group(1)})
                        enable = False

                else:
                    match = (re.search(r'(\w+)\s*\\ # Name', line))
                    if match:
                        output.update({'SPECTRUM_PROF_NAME': match.group(1)})
        except Exception as error:
            self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port) + " | Error: " + str(error)))

        return output

    def get_snr_status(self, card):
        output = {}
        try:
            if (card[0:3] == "SUA"):
                out = self.write(
                    'get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/SnrMargin')
            elif (card[0:6] == "SUVD11" or card[0:5] == "SUVD3"):
                out = self.write(
                    'get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/LineSnrMargin')
            elif (card[0:5]) == "SUVD1":
                out = self.write(
                    'get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/BandStatus')
        except:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port)))

        if card[0:6] == "SUVD11" or card[0:3] == "SUA" or card[0:5] == "SUVD3":
            try:
                for line in out.splitlines():
                    match_ds = (re.search(r'(\d+\.\w+)\s*\\ # Downstream', line))
                    match_us = (re.search(r'(\d+\.\w+)\s*\\ # Upstream', line))
                    if match_ds:
                        output.update({'SPECTRUM_SNR_DS': format(
                            float(match_ds.group(1).split('E')[0])*10**int(match_ds.group(1).split('E')[1]),'.3g')})
                    elif match_us:
                        output.update({'SPECTRUM_SNR_US': format(
                            float(match_us.group(1).split('E')[0])*10**int(match_us.group(1).split('E')[1]),'.3g')})
            except Exception as error:
                self.logging.debug(
                    'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                        + ' ' + str(self.port) + " | Error: " + str(error)))

        elif card[0:5] == "SUVD1":
            snr_ds = 0
            snr_us = 0
            band_us0 = 0
            band_ds1 = 0
            try:
                for line in out.splitlines():
                    match_band = (re.search(r'(\w+)\s*\\ # BandId', line))
                    match_snr = (re.search(r'(\w.+)\s*\\ # CurrSnrMargin', line))
                    if match_band:
                        if (match_band.group(1) == "Upstream1"):
                            band_us0 = True
                        elif (match_band.group(1) == "Downstream1"):
                            band_ds1 = True
                        else:
                            band_us0 = False
                            band_ds1 = False
                    if match_snr and band_us0:
                        snr_ds = format(
                            float(match_snr.group(1).split('E')[0]) * 10 ** int(match_snr.group(1).split('E')[1]),
                            '.3g')
                        band_us0 = 0
                    if match_snr and band_ds1:
                        snr_us = format(
                            float(match_snr.group(1).split('E')[0]) * 10 ** int(match_snr.group(1).split('E')[1]),
                            '.3g')
                        band_ds1 = 0
                output.update({'SPECTRUM_SNR_DS': (str(snr_ds))})
                output.update({'SPECTRUM_SNR_US': (str(snr_us))})
            except Exception as error:
                self.logging.debug(
                    'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                        + ' ' + str(self.port) + " | Error: " + str(error)))

        return output

    def get_out_pwr(self):
        output = {}
        try:
            out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/outputpower')
        except:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port)))
        for line in out.splitlines():
            match_ds = (re.search(r'(\w.+)\s*\\ # Downstream$', line))
            match_us = (re.search(r'(\w.+)\s*\\ # Upstream$', line))
            if match_ds:
                output.update({'SPECTRUM_PWR_DS': format(float(match_ds.group(1).split('E')[0])*10**int(match_ds.group(1).split('E')[1]),'.3g')})
            elif match_us:
                output.update({'SPECTRUM_PWR_US': format(float(match_us.group(1).split('E')[0])*10**int(match_us.group(1).split('E')[1]),'.3g')})

        return output

    def get_attenuation(self, card):
        output = {}
        try:
            if card[0:3] == "SUA":
                out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/Attenuation')
            elif card[0:3] == "SUV":
                out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/BandStatus')
        except:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port)))

        if card[0:3] == "SUA":
            for line in out.splitlines():
                match_ds = (re.search(r'(\w.+)\s*\\ # Downstream', line))
                match_us = (re.search(r'(\w.+)\s*\\ # Upstream', line))
                if match_ds:
                    output.update({'SPECTRUM_ATN_DS':
                        format(float(match_ds.group(1).split('E')[0]) * 10 ** int(match_ds.group(1).split('E')[1]), '.3g')})
                elif match_us:
                    output.update({'SPECTRUM_ATN_US':
                        format(float(match_us.group(1).split('E')[0]) * 10 ** int(match_us.group(1).split('E')[1]), '.3g')})

        else:
            atn_ds = 0
            atn_us = 0
            band_us0 = 0
            band_ds1 = 0
            for line in out.splitlines():
                match_band = (re.search(r'(\w+)\s*\\ # BandId', line))
                match_atn = (re.search(r'(\w.+)\s*\\ # CurrAttenuation', line))
                if match_band:
                    if (match_band.group(1) == "Upstream1"):
                        band_us0 = True
                    elif(match_band.group(1) == "Downstream1"):
                        band_ds1 = True
                    else:
                        band_us0 = False
                        band_ds1 = False
                if match_atn and band_us0:
                    atn_us = format(float(match_atn.group(1).split('E')[0]) * 10 ** int(match_atn.group(1).split('E')[1]),
                               '.3g')
                    band_us0 = 0
                if match_atn and band_ds1:
                    atn_ds = format(float(match_atn.group(1).split('E')[0]) * 10 ** int(match_atn.group(1).split('E')[1]),
                               '.3g')
                    band_ds1 = 0
            output.update({'SPECTRUM_ATN_DS':(str(atn_ds))})
            output.update({'SPECTRUM_ATN_US':(str(atn_us))})

        return output

    def get_standard(self):
        output = {}
        try:
            out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/Standard')
        except:
            self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port)))

        for line in out.splitlines():
          match = (re.search(r'(\w+)\s*\\ # Standard', line))
          if match:
            output.update({'SPECTRUM_STANDARD': match.group(1)})

        return output

    def get_defects(self):
        output = {}
        try:
            out = self.write('get /unit-' + (str(self.slot)) + '/port-' + (str(self.port)) + '/status/defects')
        except:
            self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' ' + self.host + ' ' + str(self.slot)
                                                    + ' ' + str(self.port)))

        # Detect if NE or FE
        lof = False
        loq = False

        for line in out.splitlines():
            match_lof = (re.search(r'(\w+)\s*\\ # LossOfFrame', line))
            match_los = (re.search(r'(\w+)\s*\\ # LossOfSignal$', line))
            match_loq = (re.search(r'(\w+)\s*\\ # LossOfSignalQuality$', line))
            match_lol = (re.search(r'(\w+)\s*\\ # LossOfLink', line))
            match_dif = (re.search(r'(\w+)\s*\\ # DataInitFailure', line))
            match_cif = (re.search(r'(\w+)\s*\\ # ConfigInitFailure', line))
            match_pif = (re.search(r'(\w+)\s*\\ # ProtocolInitFailure', line))
            match_npp = (re.search(r'(\w+)\s*\\ # NoPeer', line))
            match_lop = (re.search(r'(\w+)\s*\\ # LossOfPower', line))

            if match_lof and not lof:
              output.update({'NE_LOF': "1" if match_lof.group(1) == "true" else "0"})
              lof = True
            elif match_lof and lof:
              output.update({'FE_LOF': "1" if match_lof.group(1) == "true" else "0"})

            elif match_los:
              output.update({'NE_LOS': "1" if match_los.group(1) == "true" else "0"})

            elif match_loq and not loq:
              output.update({'NE_LOQ': "1" if match_loq.group(1) == "true" else "0"})
              loq = True
            elif match_loq and loq:
              output.update({'FE_LOQ': "1" if match_loq.group(1) == "true" else "0"})
            elif match_lol:
              output.update({'NE_LOL': "1" if match_lol.group(1) == "true" else "0"})
            elif match_dif:
              output.update({'NE_DIF': "1" if match_dif.group(1) == "true" else "0"})
            elif match_cif:
              output.update({'NE_CIF': "1" if match_cif.group(1) == "true" else "0"})
            elif match_pif:
              output.update({'NE_IF': "1" if match_pif.group(1) == "true" else "0"})
            elif match_npp:
              output.update({'NE_NATUR': "1" if match_npp.group(1) == "true" else "0"})
            elif match_lop:
              output.update({'FE_LOP': "1" if match_lop.group(1) == "true" else "0"})

        return output

    def get_xdsl_pm_data_24h(self):

        output = {}

        try:

            out = self.write('/unit-' + (str(self.slot)) + '/port-' + (str(self.port))
                             + '/pm/GetHistory24h "//*" xDSL_PORT 2050-01-01T00:00:00 1')

            for line in out.splitlines():
                match_event = (re.search(r'(\w+)\s*\\ # Event', line))
                match_elapsed = (re.search(r'(\w+)\s*\\ # ElapsedTime', line))
                match_id = (re.search(r'"(\w+)"\s*\\ # Id', line))
                match_time = (re.search(r'(\S+)\s* \\ # Timestamp$', line))

                if match_id:
                    id = match_id.group(1)
                elif match_event:
                    output.update({id: match_event.group(1)})
                elif match_time:
                    output.update({'DATE': match_time.group(1)})
                elif match_elapsed:
                    output.update({'ELAPSED': match_elapsed.group(1)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' '
                                                   + str(self.port) + " | Error: " + str(error)))

        return output

    def get_atm_pm_data_24h(self):

        output = {}

        try:

            out = self.write('/unit-' + (str(self.slot)) + '/port-' + (str(self.port))
                             + '/pm/GetHistory24h "//*" xDSL_CHANNEL 2050-01-01T00:00:00 1')

            for line in out.splitlines():
                match_event = (re.search(r'(\w+)\s*\\ # Event', line))
                match_elapsed = (re.search(r'(\w+)\s*\\ # ElapsedTime', line))
                match_id = (re.search(r'"(\w+)"\s*\\ # Id', line))
                match_time = (re.search(r'(\S+)\s* \\ # Timestamp$', line))

                if match_id:
                    id = match_id.group(1)
                elif match_event:
                    output.update({id: match_event.group(1)})
                elif match_time:
                    output.update({'DATE': match_time.group(1)})
                elif match_elapsed:
                    output.update({'ELAPSED': match_elapsed.group(1)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' '
                                                   + str(self.port) + " | Error: " + str(error)))

        return output

    def debug(self):
        self.tn.set_debuglevel(1)
        return True

class msanZhoneMalc(object):
    def __init__(self, host, user, slot, port, snmp_cmd_gen, logging, log_level):
        self.host = str(host)
        self.user = user
        self.community = 'ZhonePrivate'
        self.password = "zhone\n"
        self.tn_port = 23
        self.tn_timeout = 10
        self.login_prompt = b"login: "
        self.password_prompt = b"password: "
        self.logging = logging
        self.log_level = log_level
        self.slot = slot
        self.port = port
        self.port_index = 0
        self.cmdGen = snmp_cmd_gen


    def get_port_index(self):
        start_time = time.time()

        oid = ['.1.3.6.1.4.1.5504.3.5.7.1.6.1.' + str(self.slot) + '.' + str(self.port) + '.0.94.0']
        varBinds = snmp_get(self.host, self.community, oid, self.cmdGen, self.logging, self.log_level)
        if varBinds != -1:
            for varBind in varBinds:
                match_interval = re.search(r'(.* = (.*))', str(varBind))
                if match_interval:

                   if self.log_level:
                    total_time = time.time() - start_time
                    self.logging.debug('EXECUTION TIME %s | Function: %s | IP %s | Slot %s | Port %s '
                      % (str(total_time)[0:4], sys._getframe().f_code.co_name, self.host, str(self.slot), str(self.port)))

                   return match_interval.group(2)
        else:
            return -1

    def get_card_inventory(self):
        start_time = time.time()
        output = {}
        oid_hw = '1.3.6.1.4.1.5504.3.3.1.1.1.1.' + str(self.slot)
        oid_sw = '1.3.6.1.4.1.5504.3.3.2.1.1.1.' + str(self.slot)
        oids = [oid_hw, oid_sw]

        varBinds = snmp_get(self.host, self.community, oids, self.cmdGen, self.logging, self.log_level)

        try:
            for i, varBind in enumerate(varBinds):
                match_interval = re.search(r'(.* = (.*))', str(varBind))
                if match_interval:
                    if i == 0:
                        output.update({'BOARD_TYPE': match_interval.group(2)})
                    else:
                        output.update({'BOARD_SW': match_interval.group(2)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' '
                                                   + str(self.port) + " | Error: " + str(error)))

        if "DEBUG" in self.log_level:
            total_time = time.time() - start_time
            self.logging.debug('EXECUTION TIME %s | Function: %s | IP %s | Slot %s | Port %s '
              % (str(total_time)[0:4], sys._getframe().f_code.co_name, self.host, str(self.slot), str(self.port)))

        return output

    def get_op_data(self):
        start_time = time.time()
        output = {}

        oid_admin = ".1.3.6.1.2.1.2.2.1.7." + str(self.port_index)
        oid_oper = ".1.3.6.1.2.1.2.2.1.8." + str(self.port_index)
        oid_line_rate_ds = ".1.3.6.1.4.1.5504.5.4.1.1.7." + str(self.port_index)
        oid_line_rate_us = ".1.3.6.1.4.1.5504.5.4.1.1.6." + str(self.port_index)
        oid_co_hw = ".1.3.6.1.2.1.10.94.1.1.2.1.2." + str(self.port_index)
        oid_co_sw = ".1.3.6.1.2.1.10.94.1.1.2.1.3." + str(self.port_index)
        oid_cpe_hw = ".1.3.6.1.2.1.10.94.1.1.3.1.2." + str(self.port_index)
        oid_cpe_sw = ".1.3.6.1.2.1.10.94.1.1.3.1.3." + str(self.port_index)
        oid_snr_ds = ".1.3.6.1.2.1.10.94.1.1.3.1.4." + str(self.port_index)
        oid_snr_us = ".1.3.6.1.2.1.10.94.1.1.2.1.4." + str(self.port_index)
        oid_atn_ds = ".1.3.6.1.2.1.10.94.1.1.3.1.5." + str(self.port_index)
        oid_atn_us = ".1.3.6.1.2.1.10.94.1.1.2.1.5." + str(self.port_index)
        oid_out_pwr_ds = ".1.3.6.1.2.1.10.94.1.1.2.1.7." + str(self.port_index)
        oid_out_pwr_us = ".1.3.6.1.2.1.10.94.1.1.3.1.7." + str(self.port_index)
        oid_mabr_ds = ".1.3.6.1.2.1.10.94.1.1.2.1.8." + str(self.port_index)
        oid_mabr_us = ".1.3.6.1.2.1.10.94.1.1.3.1.8." + str(self.port_index)

        oids = [oid_admin, oid_oper, oid_co_hw, oid_co_sw, oid_cpe_hw, oid_cpe_sw, oid_snr_ds, oid_snr_us,
                oid_atn_ds, oid_atn_us, oid_line_rate_ds, oid_line_rate_us, oid_out_pwr_ds, oid_out_pwr_us,
                oid_mabr_ds, oid_mabr_us]

        varBinds = snmp_get(self.host, self.community, oids, self.cmdGen, self.logging, self.log_level)
        try:
            for oid, varBind in varBinds:

                    varBind = varBind.prettyPrint()

                    if str(oid) in oid_admin:
                        output.update({'ADMIN_STATE': varBind})
                    elif str(oid) in oid_oper:
                        if str(varBind) == '1':
                            output.update({'OPER_STATE': "Up"})
                        elif str(varBind) == '2':
                            output.update({'OPER_STATE': "Down"})
                        elif str(varBind) == '3':
                            output.update({'OPER_STATE': "Unknown"})
                        elif str(varBind) == '6':
                            output.update({'OPER_STATE': "Handshake"})
                    elif str(oid) in oid_line_rate_ds:
                        output.update({'LINE_RATE_DS': str(float(varBind)/1000.)})
                    elif str(oid) in oid_line_rate_us:
                        output.update({'LINE_RATE_US': str(float(varBind)/1000.)})
                    elif str(oid) in oid_co_hw:
                        if len(varBind) == 16:
                            output.update({'VENDOR_ID_CO_HW': varBind[0:4] + "/"
                                                              + bytes.fromhex(varBind[4:12]).decode("utf-8")
                                                              + "/" + varBind[12:]})
                        else:
                            output.update({'VENDOR_ID_CO_HW': varBind})
                    elif str(oid) in oid_co_sw:
                        output.update({'VENDOR_ID_CO_SW': varBind})
                    elif str(oid) in oid_cpe_hw:
                        output.update({'VENDOR_ID_CPE_HW': varBind})
                    elif str(oid) in oid_cpe_sw:
                        output.update({'VENDOR_ID_CPE_SW': varBind})
                        # Zhone MALC returns CPE HW version containing CPE software version at the end of string
                        cpe_hw = output['VENDOR_ID_CPE_HW']
                        cpe_hw = cpe_hw[:-len(output['VENDOR_ID_CPE_SW'])]
                        # Adjust HW name from 00005245544B0000 to 0000/RTEK/0000
                        if len(cpe_hw) == 16:
                            output.update({'VENDOR_ID_CPE_HW': cpe_hw[0:4] + "/"
                                                               + bytes.fromhex(cpe_hw[4:12]).decode("utf-8")
                                                               + "/" + cpe_hw[12:]})

                    elif str(oid) in oid_snr_ds:
                        output.update({'SPECTRUM_SNR_DS': str(float(varBind)/10.)})
                    elif str(oid) in oid_snr_us:
                        output.update({'SPECTRUM_SNR_US': str(float(varBind)/10.)})
                    elif str(oid) in oid_atn_ds:
                        output.update({'SPECTRUM_ATN_DS': str(float(varBind)/10.)})
                    elif str(oid) in oid_atn_us:
                        output.update({'SPECTRUM_ATN_US': str(float(varBind)/10.)})
                    elif str(oid) in oid_out_pwr_ds:
                        output.update({'SPECTRUM_PWR_DS': str(float(varBind)/10.)})
                    elif str(oid) in oid_out_pwr_us:
                        output.update({'SPECTRUM_PWR_US': str(float(varBind)/10.)})
                    elif str(oid) in oid_mabr_ds:
                        output.update({'SPECTRUM_MABR_DS': str(float(varBind)/1000.)})
                    elif str(oid) in oid_mabr_us:
                        output.update({'SPECTRUM_MABR_US': str(float(varBind)/1000.)})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))

        if self.log_level:
                    total_time = time.time() - start_time
                    self.logging.debug('EXECUTION TIME %s | Function: %s | IP %s | Slot %s | Port %s '
                      % (str(total_time)[0:4], sys._getframe().f_code.co_name, self.host, str(self.slot), str(self.port)))

        return output

    def get_defects(self):
      start_time = time.time()
      output = {}

      oid_defects_ds = ".1.3.6.1.2.1.10.94.1.1.2.1.6." + str(self.port_index)
      oid_defects_us = ".1.3.6.1.2.1.10.94.1.1.3.1.6." + str(self.port_index)

      # noDefect(0),
      # lossOfFraming(1),
      # lossOfSignal(2),
      # lossOfPower(3),
      # lossOfSignalQuality(4),
      # lossOfLink(5),
      # dataInitFailure(6),
      # configInitFailure(7),
      # protocolInitFailure(8),
      # noPeerAtuPresent(9)

      oids = [oid_defects_ds, oid_defects_us]
      varBinds = snmp_get(self.host, self.community, oids, self.cmdGen, self.logging, self.log_level)

      try:
          for varBind in varBinds:
              if str(varBind[0]) in oid_defects_ds and varBind[1]:
                octet_string = [str(varBind[1].prettyPrint()[2:4]),
                                str(varBind[1].prettyPrint()[4:6])]

                defects = [format(int(octet_string[0], 16), '#010b')[2:],
                           format(int(octet_string[1], 16), '#010b')[2:]]

                if defects[0] == "10000000":
                  output.update({'NE_LOF': "0", 'NE_LOS': "0", "NE_LOQ": "0",
                      "NE_LOL": "0", "NE_DIF": "0", "NE_CIF": "0",
                      "NE_IF": "0",  "NE_NATUR": "0"})
                else:
                  output.update({'NE_LOF': defects[0][1],
                    'NE_LOS': defects[0][2], "NE_LOQ": defects[0][4],
                    "NE_LOL": defects[0][5], "NE_DIF": defects[0][6],
                    "NE_CIF": defects[0][7], "NE_IF": defects[1][0],
                    "NE_NATUR": defects[1][1]})

              elif str(varBind[0]) in oid_defects_us and varBind[1]:

                octet_string = [str(varBind[1].prettyPrint()[2:4]),
                                  str(varBind[1].prettyPrint()[4:6])]

                defects = [format(int(octet_string[0], 16), '#010b')[2:],
                             format(int(octet_string[1], 16), '#010b')[2:]]

                if defects[0] == "10000000":
                  output.update({'FE_LOF': "0", 'FE_LOS': "0", "FE_LOP": "0",
                      "FE_LOQ": "0"})
                else:
                  output.update({'FE_LOF': defects[0][1], 'FE_LOS': defects[0][2],
                    "FE_LOP": defects[0][3], "FE_LOQ": defects[0][4]})

      except Exception as error:
          self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                            + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))

      if "DEBUG" in self.log_level:
          total_time = time.time() - start_time
          self.logging.debug('EXECUTION TIME %s | Function: %s | IP %s | Slot %s | Port %s '
                             % (str(total_time)[0:4], sys._getframe().f_code.co_name, self.host, str(self.slot),
                                str(self.port)))

      return output

    def get_xdsl_pm_data_24h(self):
        start_time = time.time()
        output = {}

        oid_elapsed = "1.3.6.1.2.1.10.94.1.1.6.1.23." + str(self.port_index)
        oid_ne_loss = "1.3.6.1.2.1.10.94.1.1.6.1.25." + str(self.port_index)
        oid_ne_uas = "1.3.6.1.2.1.10.94.1.1.6.1.26." + str(self.port_index)
        oid_ne_es = "1.3.6.1.2.1.10.94.1.1.6.1.28." + str(self.port_index)
        oid_ne_inits = "1.3.6.1.2.1.10.94.1.1.6.1.29." + str(self.port_index)
        oid_fe_loss = "1.3.6.1.2.1.10.94.1.1.7.1.19." + str(self.port_index)
        oid_fe_es = "1.3.6.1.2.1.10.94.1.1.7.1.21." + str(self.port_index)

        oids = [oid_elapsed, oid_ne_loss, oid_ne_uas, oid_ne_es, oid_ne_inits, oid_fe_loss, oid_fe_es]
        try:
            varBinds = snmp_get(self.host, self.community, oids, self.cmdGen, self.logging, self.log_level)

            for oid, varBind in varBinds:
                if str(oid) in oid_elapsed:
                    output.update({'ELAPSED': varBind.prettyPrint()})
                elif str(oid) in oid_ne_loss:
                    output.update({'NE_LOSS': varBind.prettyPrint()})
                elif str(oid) in oid_ne_uas:
                    output.update({'NE_UAS': varBind.prettyPrint()})
                elif str(oid) in oid_ne_es:
                    output.update({'NE_ES': varBind.prettyPrint()})
                elif str(oid) in oid_ne_inits:
                    output.update({'NE_FULL_INIT': varBind.prettyPrint()})
                elif str(oid) in oid_fe_loss:
                    output.update({'FE_LOSS': varBind.prettyPrint()})
                elif str(oid) in oid_fe_es:
                    output.update({'FE_ES': varBind.prettyPrint()})

            output.update({'DATE': str((datetime.datetime.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d"))})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' '
                                                   + str(self.port) + " | Error: " + str(error)))
        if "DEBUG" in self.log_level:
            total_time = time.time() - start_time
            self.logging.debug('EXECUTION TIME %s | Function: %s | IP %s | Slot %s | Port %s '
                               % (str(total_time)[0:4], sys._getframe().f_code.co_name, self.host, str(self.slot),
                                  str(self.port)))

        return output

    def get_atm_perf_data_24h(self):
        start_time = time.time()
        output = {}

        oid_elapsed = "1.3.6.1.2.1.10.94.1.1.10.1.17." + str(self.port_index)
        oid_ne_corr_blks = "1.3.6.1.2.1.10.94.1.1.10.1.20." + str(self.port_index)
        oid_ne_uncorr_blks = "1.3.6.1.2.1.10.94.1.1.10.1.21." + str(self.port_index)
        oid_fe_corr_blks = "1.3.6.1.2.1.10.94.1.1.11.1.20." + str(self.port_index)
        oid_fe_uncorr_blks = "1.3.6.1.2.1.10.94.1.1.11.1.21." + str(self.port_index)

        oids = [oid_elapsed, oid_ne_corr_blks, oid_ne_uncorr_blks, oid_fe_corr_blks, oid_fe_uncorr_blks]
        try:
            varBinds = snmp_get(self.host, self.community, oids, self.cmdGen, self.logging, self.log_level)

            for oid, varBind in varBinds:
                if str(oid) in oid_elapsed:
                    output.update({'ELAPSED': varBind.prettyPrint()})
                elif str(oid) in oid_ne_corr_blks:
                    output.update({'NE_CORR_BLKS': varBind.prettyPrint()})
                elif str(oid) in oid_ne_uncorr_blks:
                    output.update({'NE_UNCORR_BLKS': varBind.prettyPrint()})
                elif str(oid) in oid_fe_corr_blks:
                    output.update({'FE_CORR_BLKS': varBind.prettyPrint()})
                elif str(oid) in oid_fe_uncorr_blks:
                    output.update({'FE_UNCORR_BLKS': varBind.prettyPrint()})

            output.update({'DATE': str((datetime.datetime.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d"))})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' '
                                                   + str(self.port) + " | Error: " + str(error)))

        if "DEBUG" in self.log_level:
            total_time = time.time() - start_time
            self.logging.debug('EXECUTION TIME %s | Function: %s | IP %s | Slot %s | Port %s '
                               % (str(total_time)[0:4], sys._getframe().f_code.co_name, self.host, str(self.slot),
                                  str(self.port)))

        return output

class msanZhoneMxK(object):
    def __init__(self, host, username, slot, port, logging, log_level):
        self.tn = None
        self.host = str(host)
        self.username = username
        self.community = 'ZhonePrivate'
        self.password = "zhone\n"
        self.tn_port = 23
        self.tn_timeout = 3
        self.login_prompt = b"login: "
        self.password_prompt = b"password: "
        self.cmd_prompt = b"zSH> "
        if slot >= 10:
          self.slot = slot - 2
        else:
          self.slot = slot
        self.port = port
        self.logging = logging
        self.log_level = log_level

    def connect(self):
      try:
          self.tn = telnetlib.Telnet(self.host, self.tn_port, self.tn_timeout)
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to connect ' + self.host + " | Error: " + error))
          return -1

      try:
        self.tn.read_until(self.login_prompt, self.tn_timeout) != self.login_prompt
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to read prompt ' + self.host +  " | Error: " + error))
          return -1

      try:
          self.tn.write(self.username.encode('ascii') + b"\n")
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write user ' + self.host +  " | Error: " + error))
          return -1

      if self.password:
          try:
              self.tn.read_until(self.password_prompt, self.tn_timeout)
              self.tn.write(self.password.encode('ascii') + b"\n")
          except Exception as error:
              self.logging.debug(
                  'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write password '
                                     + self.host +  " | Error: " + error))
              return -1
      return 1

    def write(self, msg):
        self.tn.read_until(self.cmd_prompt, self.tn_timeout)
        self.tn.write(msg.encode('ascii')+b'\n')
        return self.read_until(self.cmd_prompt).decode('ascii')

    def read_until(self, value):
        try:
            return self.tn.read_until(value, self.tn_timeout)
        except:
            return -1

    def read_all(self):
        try:
            return self.tn.read_all()
        except socket.timeout:
            print("read_all socket.timeout")
            return False

    def close(self):
        try:
            self.tn.write(b"exit\n")
        except:
            self.logging.debug(
                'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' fail exit ' + self.host))

        self.tn.close()
        return True

    def get_vdsl_co_config(self):
      # get vdsl-co-config 1/2/1/0/vdsl
      output = {}
      try:
       out = self.write('get vdsl-co-config 1/' + (str(self.slot)) + '/' + (str(self.port)) + '/0/vdsl')
       for line in out.splitlines():
        match = (re.search(r'(\w+):.*{(\w+)}', line))
        if match:
          match_dict = {str(match.group(1)): match.group(2)}
          output.update(match_dict)
      except Exception as error:
           self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
            + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port)  + " | Error: " + str(error)))
      return output

    def get_vdsl_cpe_config(self):
      # get vdsl-cpe-config 1/2/1/0/vdsl
      output = {}
      try:
       out = self.write('get vdsl-cpe-config 1/' + (str(self.slot)) + '/' + (str(self.port)) + '/0/vdsl')
       for line in out.splitlines():
        match = (re.search(r'(\w+):.*{(\w+)}', line))
        if match:
          match_dict = {str(match.group(1)): match.group(2)}
          output.update(match_dict)
      except Exception as error:
           self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
            + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port)  + " | Error: " + str(error)))
      return output

    def set_interleave_rate_ds(self, rate):
      try:
        self.write('update vdsl-cpe-config rateMode = dynamic targetSnrMgn = 60 \
        maxSnrMgn = 310 minSnrMgn = 0 downshiftSnrMgn = 30 upshiftSnrMgn = 90 \
        minINP = halfsymbol maxInterleaveDelay = 8 interleaveMaxTxRate = ' + rate + '\
         1/' + str(self.slot) + '/' + str(self.port) + '/0/vdsl')

      except Exception as error:
           self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name
            + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port)  + " | Error: " + str(error)))
           return -1
      return 1

    def set_interleave_rate_us(self, rate):
      try:
        self.write('update vdsl-cpe-config rateMode = dynamic targetSnrMgn = 60 \
        maxSnrMgn = 310 minSnrMgn = 0 downshiftSnrMgn = 30 upshiftSnrMgn = 90 minINP = halfsymbol \
        maxInterleaveDelay = 8 interleaveMaxTxRate = ' + rate + ' 1/ + self.slot' + '/' + self.port + '/0/vdsl')
      except Exception as error:
           self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name
            + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port)  + " | Error: " + str(error)))
           return -1
      return 1

    def set_interleave_mode(self):
      try:
        self.write('update vdsl-config line-type = interleavedonly \
        1/' + (str(self.slot)) + '/' + (str(self.port)) + '/0/vdsl')
      except Exception as error:
        self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name
        + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port)  + " | Error: " + str(error)))
        return -1
      return 1

    def debug(self):
        self.tn.set_debuglevel(1)
        return True

class msanNokia(object):
    'Class for Nokia functions defines methods for getting MSAN information'

    def __init__(self, host, slot, port, logging, log_level, username="engenharia", password="#engenharia21\n"):
        self.tn = None
        self.username = username
        self.password = password
        self.host = str(host)
        self.tn_port = 23
        self.timeout = 3
        self.login_prompt = b"login: "
        self.password_prompt = b"password: "
        self.cmd_prompt = b'>#'
        self.slot = slot
        self.port = port
        self.logging = logging
        self.log_level = log_level


    def connect(self):
      try:
          self.tn = telnetlib.Telnet(self.host, self.tn_port, self.timeout)
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to connect ' + self.host + " | Error: " + str(error)))
          return -1

      try:
        self.tn.read_until(self.login_prompt, self.timeout) != self.login_prompt
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to read prompt ' + self.host + " | Error: " + str(error)))
          return -1

      try:
          self.tn.write(self.username.encode('ascii') + b"\n")
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write user ' + self.host +  " | Error: " + str(error)))
          return -1

      if self.password:
          try:
              self.tn.read_until(self.password_prompt, self.timeout)
              self.tn.write(self.password.encode('ascii') + b"\n")
              out = self.tn.read_until(self.cmd_prompt, self.timeout)
              if self.cmd_prompt not in out:
                  self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' wrong password '
                                     + self.host ))
                  return -1
          except socket.timeout as error:
              self.logging.debug(
                  'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write password '
                                     + self.host +  " | Error: " + error))
              return -1
      return 1

    def write(self, msg):
        try:
            self.tn.write(msg.encode('ascii')+b'\n')
        except Exception as error:
            self.logging.debug(
                'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write command '
                                   + self.host + " | Error: " + error))

        return self.read_until(self.cmd_prompt).decode('ascii')

    def read_until(self, value):
        try:
            return self.tn.read_until(value, self.timeout)
        except Exception as error:
            self.logging.debug(
                'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' could not read command output'
                                   + self.host + " | Error: " + error))

    def read_all(self):
        try:
            return self.tn.read_all()
        except socket.timeout:
            print("read_all socket.timeout")
            return False

    def close(self):
        try:
            self.tn.write(b"logout\n")
        except:
            self.logging.debug(
                'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' fail exit ' + self.host))

        self.tn.close()
        return True

    def debug(self):
        self.tn.set_debuglevel(1)
        return True


    def disable_prompt_alarms(self):
        # disable prompt alarms that might interfere on the output
        try:
            self.write('environment inhibit-alarms')
            self.write('exit all')
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
            return -1
        return 0

    def set_command(self, cmd):
        # send command to device
        output = {}
        try:
            out = self.write(cmd)
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return out

    def get_ip_interfaces(self, vpn = 0):
      # get ip interfaces for router instance
        output = {}

        if_data = None
        ip_addr = None
        try:
            if (vpn):
                out = self.write('show router ' + str(vpn) + ' interface')
            else:
                out = self.write('show router interface')

            for line in out.splitlines():
                match_if_name = re.search(r'(\w+)\s+(\w+)\s+(\w+/\w+)\s+(\w+)\s+(.*)', line)
                match_if_ip = re.search(r'(\d+.\d+.\d+.\d+/\d+)', line)
                if(match_if_name):
                    if_data = {match_if_name.group(1):{'admin_state':match_if_name.group(2),
                                                       'oper_state':match_if_name.group(3),
                                                       'if_mode':match_if_name.group(4),
                                                       'if_port':match_if_name.group(5)}}
                elif(match_if_ip):
                    ip_addr = str(match_if_ip.group(1))
                if ip_addr is not None and if_data is not None:
                    for k in if_data.keys():
                        if_data[k].update({'ip_addr':ip_addr})
                        output.update({k:if_data[k]})
                    if_data = None
                    ip_addr = None
        except Exception as error:
           self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
            + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port)  + " | Error: " + str(error)))
        return output


    def get_isis_neighbors(self):
        # get isis neighbors
        output = {}
        neighbor_count=0
        try:
            out = self.write('show router isis adjacency')

            for line in out.splitlines():
                match = re.search(r'(.*\S)\s+(L\d)\s+(\w+)\s+(\d+)\s+(\w+\d+)', line)
                if (match):
                    output.update({str(match.group(5)):str(match.group(1))})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return output


    def get_active_routes(self, vpn=0, route=""):
        # get active routes
        output = {}
        route_key = None
        try:
            if not vpn:
                out = self.write('show router route-table ' + route)
            else:
                out = self.write('show router ' + str(vpn) + ' route-table ' + str(route))

            for line in out.splitlines():
                match_route = re.search(r'((?:\d{1,3}\.){3}\d{1,3}\/\d+)\s+(\w+)\s+(\w+...)\s+(\w+)\s+(\d+)', line)
                match_next_hop = re.search(r'(\d+.\d+.\d+.\d+)\s+(\d+)', line)
                if match_route:
                    route_key = str(match_route.group(1))
                    output.update({route_key:{'type':match_route.group(2), 'proto':match_route.group(3),
                                                        'age':match_route.group(4),'metric':match_route.group(5)}})
                elif match_next_hop:
                    output[route_key].update({'next_hop':match_next_hop.group(1)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(route) + " | Error: " + str(error)))

        return output

    def get_pim_neighbor(self, vpn=0):
        # get pim neighbors
        output = {}
        try:
            if not vpn:
                out = self.write('show router pim neighbor')
            else:
                out = self.write('show router ' + str(vpn) + 'pim neighbor')

            for line in out.splitlines():
                match = re.search(r'(\w+)\s+(\d+)\s+(\w+ \d+:\d+:\d+)\s+(\w+ \d+:\d+:\d+)\s+(\d+)', line)
                if (match):
                    output.update({str(match.group(1)):{'nbr_dr_prty':match.group(2), 'uptime':match.group(3),
                                                        'expiry_time':match.group(4),'holdtime':match.group(5)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return output

    def get_ssm_mapping(self, vpn=0):
        # get pim neighbors
        output = {}
        try:
            if not vpn:
                out = self.write('show router igmp ssm-translate')
            else:
                out = self.write('show router ' + vpn + 'ssm-translate')

            for line in out.splitlines():
                match = re.search(r'<(\d+.\d+.\d+.\d+) - (\d+.\d+.\d+.\d+)>\s+(\d+.\d+.\d+.\d+)', line)
                if (match):
                    output.update({str(match.group(3)):{'range_start':match.group(1), 'range_end':match.group(2)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return output

    def get_sdp_status(self):
        # get service sdp status
        output = {}
        try:
            out = self.write('show service sdp-using')
            for line in out.splitlines():
                match = re.search(r'(\d+)\s+(\d+:\d+)\s+(\w+)\s+(\d+.\d+.\d+.\d+.)\s+(\w+)\s+(\d+)\s+(\w+)', line)
                if (match):
                    output.update({str(match.group(1)):{'sdp_id':match.group(2), 'type':match.group(3),
                                                        'far_end':match.group(4), 'oper_status':match.group(5),
                                                        'ingress_label':match.group(6), 'egress_label':match.group(7)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return output

    def get_route_arp(self, vpn=0, interface=""):
        # show mac from other ip interfaces
        output = {}
        try:
            if not vpn:
                out = self.write('show router arp ' + interface)
            else:
                out = self.write('show router ' + str(vpn) + ' arp ' + interface)

            for line in out.splitlines():
                match = re.search(r'(\d+.\d+.\d+.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
                if (match):
                    output.update({str(match.group(1)):{'mac_addr':match.group(2), 'expiry':match.group(3),
                                                        'type':match.group(4), 'interface':match.group(5)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))

        return output

    def get_mcast_chn_conf(self):
        # show list of channels available for receiving
        output = {}
        try:
            out = self.write('info configure mcast chn flat')
            for line in out.splitlines():
                match = re.search(r'(\d+.\d+.\d+.\d+).*end-ip-addr\s(\d+.\d+.\d+.\d+)', line)
                if (match):
                    output.update({str(match.group(1)):{'end_range':match.group(2)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return output

    def get_mrouter_ports(self, svlan="4000"):
        # show list of channels available for receiving
        output = {}
        try:
            out = self.write('show service id ' + svlan + ' igmp-snooping mrouters')

            for line in out.splitlines():
                match = re.search(r'(\d+.\d+.\d+.\d+)\s+(\S+)\s+(\S+\s\S+)\s+(\w+)\s+(\w+)', line)
                if match:
                    output.update({str(match.group(1)):{'port_id':match.group(2), 'uptime':match.group(3), 'expire':match.group(4), 'version':match.group(5)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                 + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(self.port) + " | Error: " + str(error)))
        return output

    def get_service_IDs(self):
        # Get all service IDs
        output = {}
        try:
            out = self.write('show service service-using')

            for line in out.splitlines():
                match = re.search(r'(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\d+)', line)
                if (match):
                    output.update({str(match.group(1)): {{'svc_type': match.group(2)},
                                                         {'admin_state': match.group(3)},
                                                         {'customer_id': match.group(4)}}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_system_security_profile(self, profile):

        output = {}
        try:
            out = self.write('info configure system security profile ' + profile + ' flat')
            for line in out.splitlines():
                match = re.search(r'(security)\s(read|write)', line)
                if match:
                    output.update({match.group(1): match.group(2)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_sap_info(self):
        output = {}
        try:
            out = self.write('show service sap-using')
            for line in out.splitlines():
                match = re.search(r'(\S+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)', line)
                if match:
                    output.update({match.group(1): match.group(2), "ingress-filter":match.group(3),
                                   "egress-filter": match.group(4), "admin_state": match.group(4),
                                   "oper_state": match.group(5)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_mcast_active_groups(self, group=""):

        #===========================================================================================================================================
		#grp-membership table
		#==================================================================================================================================================
		#mcast-grp-addr |vlan-id|mcast-src-addr |port                                      |state    |status
		#---------------+-------+---------------+------------------------------------------+---------+----------------------------------------------------
		#239.130.1.0     3013    0.0.0.0         vlan:1/1/1/3/64/1/1:20                     full-view dynamic
		#239.130.1.0     3013    0.0.0.0         vlan:1/1/1/6/61/1/1:20                     full-view dynamic
		#239.130.1.0     3013    0.0.0.0         vlan:1/1/3/1/10/1/1:20                     full-view dynamic

        output = {}
        try:
            out = self.write('show mcast grp-membership ' + group)
            for line in out.splitlines():
                match = re.search(r'(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\w+)', line)
                if match:
                    if match.group(1) in output:    
                        output[match.group(1)]['port'].append(match.group(4))
                    else:
                        output.update({match.group(1):{'vlan-id':match.group(2),'mcast-src-addr':match.group(3),
                                      'port':[match.group(4)],'state':match.group(5),'status':match.group(6)}})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_transceiver_data(self, port=""):
        output = {}
        try:
            out = self.write('show equipment transceiver-inventory ' + port)
            for line in out.splitlines():
                match = re.search(r'(\S+)\s+(no-error|cage-empty)\s+(\S+)\s+(not-available|\S+ \S+)\s+(\S+)\s+(\S+)', line)
                if match:
                    output.update({match.group(1):{'inventory-status':match.group(2),'alu-part-num':match.group(3),'tx-wavelength':match.group(4),
                                  'fiber-type':match.group(5),'rssi-sfptype':match.group(6)}})

        except Exception as error:
             self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                               + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
											self.port) + " | Error: " + str(error)))

        return output

class msanHuawei(object):
    'Class for Huawei functions defines methods for getting Huawei devices information'

    def __init__(self, host, slot, port, logging, log_level, username='root', password='admin'):
        self.tn = None
        self.username = username
        self.password = password
        self.host = str(host)
        self.tn_port = 23
        self.timeout = 3
        self.login_prompt = b">>User name:"
        self.password_prompt = b">>User password:"
        self.cmd_prompt_exec = b'>'
        self.cmd_prompt = b'#'
        self.slot = slot
        self.port = port
        self.logging = logging
        self.log_level = log_level

    def connect(self):
      try:
          self.tn = telnetlib.Telnet(self.host, self.tn_port, self.timeout)
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to connect ' + self.host + " | Error: " + str(error)))
          return -1

      try:
        self.tn.read_until(self.login_prompt, self.timeout) != self.login_prompt
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to read prompt ' + self.host + " | Error: " + str(error)))
          return -1

      try:
          self.tn.write(self.username.encode('ascii') + b"\n")
      except Exception as error:
          self.logging.debug(
              'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write user ' + self.host +  " | Error: " + str(error)))
          return -1

      if self.password:
          try:
              self.tn.read_until(self.password_prompt, self.timeout)
              self.tn.write(self.password.encode('ascii') + b"\n")
              out = self.tn.read_until(self.cmd_prompt_exec, self.timeout)
              if self.cmd_prompt_exec not in out:
                  self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' wrong password '
                                     + self.host))
          except socket.timeout as error:
              self.logging.debug(
                  'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write password '
                                     + self.host +  " | Error: " + error))
              return -1

          # Run enable command
          try:
              self.tn.read_until(self.cmd_prompt_exec, self.timeout)
              self.tn.write("en".encode('ascii') + b"\n")
              out = self.tn.read_until(self.cmd_prompt)
              if self.cmd_prompt not in out:
                  self.logging.debug('EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' wrong password '
                                     + self.host))
          except Exception as error:
              self.logging.debug(
                  'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to raise to cmd mode'
                                     + self.host + " | Error: " + error))
      return 1


    def write(self, msg):
        try:
            #self.tn.read_until(self.cmd_prompt, self.timeout)
            self.tn.write(msg.encode('ascii')+b'\n')
        except Exception as error:
            self.logging.debug(
                'EXCEPTION: %s' % (sys._getframe().f_code.co_name + ' fail to write command '
                                   + self.host + " | Error: " + error))
        return self.tn.read_until(self.cmd_prompt).decode('ascii')

    def read_until(self, value):
        try:
            return self.tn.read_until(value, self.timeout)
        except:
            return -1

    def read_all(self):
        try:
            return self.tn.read_all()
        except socket.timeout:
            print("read_all socket.timeout")
            return False

    def close(self):
        try:
            self.tn.close()
        except:
            self.logging.debug(
                'EXCEPTION:  %s' % (sys._getframe().f_code.co_name + ' fail exit ' + self.host))

        self.tn.close()
        return True

    def set_command(self, cmd):
        # send command to device
        output = {}
        try:
            out = self.write(cmd)
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                        self.port) + " | Error: " + str(error)))
        return out

    def get_ip_interfaces(self, vpn=""):
        # Interface        IP Address/Mask       Physical    Protocol
        #meth0            10.11.104.2/24        down        down
        #null0            unassigned            up          up(s)
        #vlanif8          10.23.38.186/30       up          up
        #vlanif400        10.29.48.1/20         up          up
        #vlanif3005       10.58.250.98/30       up          up
        #vlanif3006       10.58.250.102/30      up          up
        #vlanif3007       10.58.250.106/30      up          up
        #vlanif3042       10.58.240.182/30      up          up

        output = {}
        try:
            out = self.write('display ip interface brief')
            for line in out.splitlines():
                match = re.search(r'(\w+)\s+(\d+.\d+.\d+.\d+\/\d+)\s+(\w+)\s+(\w+)', line)
                if match:
                    output.update({match.group(1):{'ip_addr':match.group(2),'admin_state':match.group(3),
                                                   'oper_state':match.group(4)}})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_vlan_description(self, vlanid):
        output = {}
        try:
            out = self.write('display vlan ' + str(vlanid))
            for line in out.splitlines():
                match = re.search(r'VLAN description: (\w+)', line)
                if match:
                    output.update({'description':match.group(1)})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_mcast_prefix(self):
        output = {}
        try:
            out = self.write('display current-configuration section btv | include \"program add\"')
            for line in out.splitlines():
                match_single = re.search(r'add ip (\d+.\d+.\d+.\d+)', line)
                match_range = re.search(r'(\d+.\d+.\d+.\d+)\sto-ip\s(\d+.\d+.\d+.\d+)', line)
                if match_single:
                    output.update({match_single.group(1):{'end_range': match_single.group(1)}})
                elif match_range:
                    output.update({match_range.group(1):{'end_range': match_range.group(2)}})

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_mrouter_ports(self):

        # Huawei mrouter port refers to uplink port
        #  ----------------------------------------------------------------------------
        #   Port  | VLAN |  IGMP   | IGMP V2 router  | IGMP IPv6 | IGMP IPv6 V1 router
        #         |      | version | present timer(s)| version   | present timer(s)
        #  ----------------------------------------------------------------------------
        #  0/20/0     3013   V2          0                V2           0
        #  ----------------------------------------------------------------------------
        #  Total: 1

        output = {}
        try:
            out = self.write('display igmp uplink-port all')
            for line in out.splitlines():
                match = re.search(r'(\S+)\s+(\d+)\s+(\w+)\s+(\d+)\s+(\w+)\s+(\w+)\s+', line)
                if match:
                    output.update({match.group(1):{'vlan': match.group(2), 'version': match.group(2),
                                    'timer': match.group(3),'v6_version': match.group(4)},'v6_timer': match.group(5)})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def get_active_routes(self, vpn="", route=""):
        # Huawei vpn is vpn-instance
        #                  display ip routing-table
        # Route Flags: R - relay, D - download to fib
        # ------------------------------------------------------------------------------
        # Routing Tables: Public
        #         Destinations : 12       Routes : 12

        # Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface
        #
        #        0.0.0.0/0   Static  60   0          RD   10.142.124.1    vlanif80
        #   10.142.124.0/24  Direct  0    0           D   10.142.124.138  vlanif80
        # 10.142.124.138/32  Direct  0    0           D   127.0.0.1       vlanif80
        #     10.200.0.0/16  Static  60   0          RD   10.200.38.1     meth0
        #    10.200.38.0/23  Direct  0    0           D   10.200.38.106   meth0
        #      127.0.0.1/32  Direct  0    0           D   127.0.0.1       InLoopBack0
        #   172.18.6.122/31  Direct  0    0           D   172.18.6.123    vlanif4000
        #   172.18.6.123/32  Direct  0    0           D   127.0.0.1       vlanif4000
        #    177.16.30.0/23  Static  60   0          RD   10.200.38.1     meth0
        #  192.168.129.0/24  Static  60   0          RD   10.200.38.1     meth0

        output = {}
        try:
            out = self.write('display ip routing-table ' + route)
            for line in out.splitlines():
                match = re.search(r'(\S+)\s+(\w+)\s+(\d+)\s+(\d+)\s+(\w+)\s+(\S+)\s+(\S+)', line)
                if match:
                    output.update({match.group(1): {'proto': match.group(2), 'next_hop': match.group(6),
                                                    'ip_if': match.group(7)}})
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
        return output

    def debug(self):
        self.tn.set_debuglevel(1)
        return True

class msanNokia7342(object):
    def __init__(self, host, slot, port, logging, log_level, username="sigres1", password="s1gr3s1@OLT",key_filename="None"):
    #def __init__(self, host, slot, port, logging, log_level, username="g0041078", password="Lu2ta4!W",key_filename="None"):
        self.tn = None
        self.username = username
        self.password = password
        self.host = str(host)
        self.tn_port = 23
        self.timeout = 3
        self.login_prompt = b"login: "
        self.password_prompt = b"password: "
        self.cmd_prompt = b'>#'
        self.key_filename = key_filename
        self.connected = False
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.timeout = 3
        self.ssh.port = 22
        self.ssh.shell = None
        self.ssh.buffer_size = 65535
        self.slot = slot
        self.port = port
        self.logging = logging
        self.log_level = log_level

        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography import utils as crypto_utils

        def _override_check_dsa_parameters(parameters):
            """Override check_dsa_parameters from cryptography's dsa.py

            Allows for shorter or longer parameters.p to be returned from the server's host key. This is a
            HORRIBLE hack and a security risk, please remove if possible!
            """
            # if utils.bit_length(parameters.p) not in [1024, 2048, 3072]:
            # raise ValueError("p is {}, must be exactly 1024, 2048, or 3072 bits long".format(utils.bit_length(parameters.p)))
            if crypto_utils.bit_length(parameters.q) not in [160, 256]:
                raise ValueError("q must be exactly 160 or 256 bits long")

            if not (1 < parameters.g < parameters.p):
                raise ValueError("g, p don't satisfy 1 < g < p.")

        dsa._check_dsa_parameters = _override_check_dsa_parameters

    def connect_ssh(self):
        self.ssh.load_system_host_keys()
        #print("trying to connect to " + self.host)
        try:
            self.ssh.connect(self.host, self.ssh.port, username=self.username, password=self.password,
                                allow_agent=False, look_for_keys=False, timeout=self.ssh.timeout)

        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                               + ' ' + self.host + ' fail to open connection' + " | Error: " + str(error))) 
            return -1

        try:
            self.ssh.shell = self.ssh.invoke_shell()
            self.ssh.shell.recv(self.ssh.buffer_size)
        except Exception:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                               + ' ' + self.host + ' fail to invoke shell' + " | Error: " + str(error)))
            return -1

        return 1

    def set_cmd(self, cmd):
        try:
            self.ssh.shell.send(cmd + "\n")
            sleep(0.5)
            out = self.ssh.shell.recv(self.ssh.buffer_size).splitlines()
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
            return -1
        return out

    def close_ssh(self):
        try:
            self.ssh.shell.send("logout\n")
            sleep(0.5)
            self.ssh.shell.recv(self.ssh.buffer_size).splitlines()
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name \
                              + ' ' + self.host  + " | Error: " + str(error)))
            return -1
        return 0

    def disable_prompt_alarms(self):
        # disable prompt alarms that might interfere on the output
        try:
            self.ssh.shell.send("environment inhibit-alarms\n")
            sleep(0.2)
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
            return -1
        return 0


    def get_sw_info(self):
        try:
            self.ssh.shell.send("show software-mngt oswp\n")
            sleep(0.5)
            for line in self.ssh.shell.recv(self.ssh.buffer_size).splitlines():
                print(line.decode('utf-8'))
        except Exception as error:
            self.logging.debug('EXCEPTION:  %s' % (sys._getframe().f_code.co_name
                                                   + ' ' + self.host + ' ' + str(self.slot) + ' ' + str(
                self.port) + " | Error: " + str(error)))
            return -1
        return 0
