import sys
import json
import requests
import pprint
import ConfigParser
import dns.resolver
import logging

class ibconn:
    """
    Helper Objects for Infoblox WAPI Connections
    """
    def __init__(self, conffile):
        config = ConfigParser.ConfigParser()
        try:
            config.read(conffile)
        except:
            print "failed opening config file, giving up"
            sys.exit(0)
        try:
            self.ib_address = config.get('IB', 'address')
            self.username = config.get('IB', 'username')
            self.path = config.get('IB', 'path')
            self.password = config.get('IB', 'password')
            self.version = config.get('IB', 'version')
            if config.get('IB', 'verify') == 'True':
                self.verify = True
            else:
                self.verify = False
        except:
            print "conf file appears to be corrupt or does not contain all needed values to set up IB connection"
            sys.exit(0)

        if self.version == '1.2':
            self.ib_fixedaddr_fields = 'agent_circuit_id,agent_remote_id,always_update_dns,bootfile,bootserver,client_identifier_prepend_zero,comment,ddns_domainname,ddns_hostname,deny_bootp,dhcp_client_identifier,disable,discovered_data,enable_ddns,extattrs,ignore_dhcp_option_list_request,ipv4addr,mac,match_client,ms_options,ms_server,name,network,network_view,nextserver,options,pxe_lease_time,use_bootfile,use_bootserver,use_ddns_domainname,use_deny_bootp,use_enable_ddns,use_ignore_dhcp_option_list_request,use_nextserver,use_options'
            self.ib_ipv4address_fields = 'dhcp_client_identifier,extattrs,fingerprint,ip_address,is_conflict,lease_state,mac_address,names,network,network_view,objects,status,types,usage,username'
            self.ib_lease_fields = 'address,billing_class,binding_state,client_hostname,cltt,discovered_data,ends,hardware,ipv6_duid,ipv6_iaid,ipv6_preferred_lifetime,ipv6_prefix_bits,network,network_view,never_ends,never_starts,next_binding_state,on_commit,on_expiry,on_release,option,protocol,served_by,server_host_name,starts,tsfp,tstp,uid,username,variable'
            self.ib_macfilteraddress_fields = 'authentication_time,comment,expiration_time,extattrs,filter,guest_custom_field1,guest_custom_field2,guest_custom_field3,guest_custom_field4,guest_email,guest_first_name,guest_last_name,guest_middle_name,guest_phone,is_registered_user,mac,never_expires,reserved_for_infoblox,username'
            self.ib_mx_fields = 'comment,dns_mail_exchanger,dns_name,mail_exchanger,name,preference,ttl,use_ttl,view,zone'
            self.ib_network_fields = 'network'
            self.ib_ptr_fields = 'comment,disable,discovered_data,dns_name,dns_ptrdname,extattrs,ipv4addr,ipv6addr,name,ptrdname,ttl,use_ttl,view,zone'
            self.ib_range_fields = 'always_update_dns,authority,bootfile,bootserver,comment,ddns_domainname,ddns_generate_hostname,deny_all_clients,deny_bootp,disable,email_list,enable_ddns,enable_dhcp_thresholds,enable_email_warnings,enable_ifmap_publishing,enable_snmp_warnings,end_addr,exclude,extattrs,failover_association,fingerprint_filter_rules,high_water_mark,high_water_mark_reset,ignore_dhcp_option_list_request,is_split_scope,known_clients,lease_scavenge_time,logic_filter_rules,low_water_mark,low_water_mark_reset,mac_filter_rules,member,ms_options,ms_server,nac_filter_rules,name,network,network_view,nextserver,option_filter_rules,options,pxe_lease_time,recycle_leases,relay_agent_filter_rules,server_association_type,start_addr,update_dns_on_lease_renewal,use_authority,use_bootfile,use_ddns_domainname,use_ddns_generate_hostname,use_deny_bootp,use_email_list,use_enable_dhcp_thresholds,use_enable_ifmap_publishing,use_ignore_dhcp_option_list_request,use_known_clients,use_nextserver,use_options,use_recycle_leases,use_unknown_clients,use_update_dns_on_lease_renewal'
            self.ib_zone_auth_fields = 'address,allow_active_dir,allow_gss_tsig_for_underscore_zone,allow_gss_tsig_zone_updates,allow_query,allow_transfer,allow_update,allow_update_forwarding,comment,copy_xfer_to_notify,create_underscore_zones,disable,disable_forwarding,display_domain,dns_fqdn,dns_soa_email,dns_soa_mname,dnssec_key_params,effective_check_names_policy,effective_record_name_policy,extattrs,external_primaries,external_secondaries,fqdn,grid_primary,grid_primary_shared_with_ms_parent_delegation,grid_secondaries,is_dnssec_enabled,is_dnssec_signed,last_queried,locked,locked_by,mask_prefix,ms_ad_integrated,ms_allow_transfer,ms_allow_transfer_mode,ms_ddns_mode,ms_managed,ms_primaries,ms_read_only,ms_secondaries,ms_sync_master_name,network_associations,network_view,notify_delay,ns_group,parent,prefix,primary_type,record_name_policy,records_monitored,rr_not_queried_enabled_time,soa_default_ttl,soa_email,soa_expire,soa_mname,soa_negative_ttl,soa_refresh,soa_retry,soa_serial_number,srgs,update_forwarding,use_allow_active_dir,use_allow_transfer,use_allow_update,use_allow_update_forwarding,use_check_names_policy,use_copy_xfer_to_notify,use_dnssec_key_params,use_external_primary,use_grid_zone_timer,use_import_from,use_record_name_policy,use_soa_email,use_soa_mname,using_srg_associations,view,zone_format,zone_not_queried_enabled_time'
            self.ib_zone_delegated_fields = 'address,comment,delegate_to,delegated_ttl,disable,display_domain,dns_fqdn,enable_rfc2317_exclusion,extattrs,fqdn,locked,locked_by,mask_prefix,ms_ad_integrated,ms_ddns_mode,ms_managed,ms_read_only,ms_sync_master_name,parent,prefix,use_delegated_ttl,using_srg_associations,view,zone_format'

    def create_range(self, start_addr, end_addr, member, failover_association, network, network_view, dhcpopt_dns, dhcpopt_router, dhcpopt_searchsuffix=None, comment=None, email_list=None, enable_email_warnings="False", high_water_mark=None, high_water_mark_reset=None, mac_filter_rules=None):
        """
        Create a new dhcp range
        """

        headers={'Content-type': 'application/json', 'Accept': 'text/plain'}
        dns_opt = {'name':'Router', 'num': 3, 'use_option': True, 'value': dhcpopt_dns, 'vendor_class': 'DHCP'}
        router_opt = {'name':'DNS server', 'num':6, 'use_option': True, 'value': dhcpopt_router, 'vendor_class': 'DHCP'}
        searchsuffix_opt = {'name':'DNS search suffix', 'num': 15, 'use_option': True, 'value': dhcpopt_searchsuffix, 'vendor_class': 'DHCP'}
        dhcpopts = [dns_opt, router_opt, searchsuffix_opt]
        paramset = {'start_addr':start_addr,'end_addr':end_addr,'member':member, 'failover_association':failover_association, 'network':network,'network_view':network_view, 'use_options':'True', 'options':dhcpopts}
        logging.debug(json.dumps (paramset, separators=(',',':'), sort_keys=True, indent=4))
        r = requests.post('https://' + self.ib_address + self.path + self.version + '/range', data=json.dumps(paramset), headers=headers, auth=(self.username, self.password), verify=self.verify)
        logging.debug(r.text)
        logging.debug(r.headers)

    def create_zone_delegated(self, view, fqdn, dns1, dns1ip, dns2=None, dns2ip=None, dns3=None, dns3ip=None, dns4=None, dns4ip=None):
        """
        Create a new delegated DNS Zone, specifying between 1 and 4 nameservers for the new zone
        """

        headers={'Content-type': 'application/json', 'Accept': 'text/plain'}
        dnslist = [{'address':dns1ip, 'name':dns1}]
        if dns2 is not None:
            dnslist.append({"address":dns2ip, "name":dns2})
        if dns3 is not None:
            dnslist.append({"address":dns3ip, "name":dns3})
        if dns4 is not None:
            dnslist.append({"address":dns4ip, "name":dns4})
        paramset = {'fqdn': fqdn, 'delegate_to':dnslist, 'view':view}
        logging.debug(json.dumps (paramset, separators=(',',':'), sort_keys=True, indent=4))
        r = requests.post('https://' + self.ib_address + self.path + self.version + '/zone_delegated', data=json.dumps(paramset), headers=headers, auth=(self.username, self.password), verify=self.verify)
        logging.debug(r.text)
        logging.debug(r.headers)

    def get_fixedaddress(self, keyfield, key, numresults=100, fields=None):
        """
        Get Fixed Address from Infoblox WAPI
        """

        if fields is None:
            fields = self.ib_fixedaddr_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/fixedaddress?' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_ipv4address(self, keyfield, key, cidr_net, network_view='default', numresults=1000, fields=None):
        """
        Get ipv4address information from Infoblox WAPI
        """
        if fields is None:
            fields = self.ib_ipv4address_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/ipv4address?' + keyfield + '=' + key + '&network=' + cidr_net + '&network_view=' + network_view + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()        

    def get_lease(self, keyfield, key, numresults=1000, fields=None):
        """
        Get DHCP Lease information keyfield can be MAC or IP
        """

        if fields is None:
            fields = self.ib_lease_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/lease?' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_mx(self, view, keyfield, key, numresults=1000, fields=None):
        """
        Get MX record information
        """
        if fields is None:
            fields = self.ib_mx_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/record:mx?view=' + view + '&' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_macfilteraddress(self, keyfield, key, numresults=100, fields=None):
        """
        Returns the MAC Filter for a device, accepts MAC or IP and keyfield
        """

        if fields is None:
            fields = self.ib_macfilteraddress_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/macfilteraddress?' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_network(self, keyfield, key, numresults=1000, fields=None):
        """
        Get networks defined in IB
        """

        if fields is None:
            fields = self.ib_network_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/network?' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_ptr(self, keyfield, key, numresults=100, fields=None):
        """
        Returns the ptr for the specified search
        """
        
        if fields is None:
            fields = self.ib_ptr_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/record:ptr?' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()        

    def get_range(self, keyfield, key, numresults=100, fields=None):
        """
        Returns a dhcp range
        """

        if fields is None:
            fields = self.ib_range_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/range?' + keyfield + '=' + key + '&_return_fields=' + fields + '&_max_results=-' + str(numresults), auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_record_a(self, keyfield, key, numresults=100, fields=None):
        """
        Returns an A record
        """
        if fields is None:
            fields = self.ib_record_a_fields

    def get_zone_auth(self, keyfield, key, fields=None):
        """
        Returns Information about a zone that Infoblox is authoritative for.
        """

        if fields is None:
            fields = self.ib_zone_auth_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/zone_auth?' + keyfield + '=' + key + '&_return_fields=' + fields, auth=(self.username, self.password), verify=self.verify)
        return r.json()

    def get_zone_delegated(self, keyfield, key, fields=None):
        """
        Return information about delegated DNS Zones
        """

        if fields is None:
            fields = self.ib_zone_delegated_fields
        r = requests.get('https://' + self.ib_address + self.path + self.version + '/zone_delegated?' + keyfield + '=' + key + '&_return_fields=' + fields, auth=(self.username, self.password), verify=self.verify)
        return r.json()

