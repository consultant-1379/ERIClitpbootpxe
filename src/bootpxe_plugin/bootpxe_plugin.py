##############################################################################
# COPYRIGHT Ericsson AB 2020
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import redfish
from redfish.rest.v1 import BadRequestError, InvalidCredentialsError, \
    RetriesExhaustedError, DecompressResponseError
import imp
import os
import time

from litp.core.plugin import Plugin
from litp.core.execution_manager import (CallbackTask,
                                         CallbackExecutionException,
                                         PlanStoppedException)
from litp.plan_types.deployment_plan import deployment_plan_tags
from litp.core.validators import ValidationError
from litp.core.litp_logging import LitpLogger

_LOG = LitpLogger()
_CLOUD_REDFISH_PATH = '/opt/ericsson/nms/litp/bin/redfishtool.cloud'


class Timeout(object):
    """
    Utility class for execution sleep
    """

    def __init__(self, seconds):
        self._wait_for = seconds
        self._start_time = Timeout.time()

    @staticmethod
    def time():
        return time.time()

    @staticmethod
    def sleep(seconds):
        time.sleep(seconds)

    def has_elapsed(self):
        return self.get_elapsed_time() >= self._wait_for

    def get_elapsed_time(self):
        return Timeout.time() - self._start_time


class BootpxePlugin(Plugin):
    """
    LITP bootpxe plugin
    """

    @staticmethod
    def _is_cloud_env():
        """
        A check to determine if we are on cloud.
        """
        try:
            if os.path.isfile(_CLOUD_REDFISH_PATH) and \
                    os.access(_CLOUD_REDFISH_PATH, os.X_OK):
                return True
        except OSError:
            return False
        else:
            return False

    def _get_password(self, context, user, pkey):
        """
        Fetch the Keyring password, via the Context
        for a certain PasswordKey::User pair.
        """

        return context.get_password(pkey, user)

    def _login(self, ipaddr, user, pwd):
        """
        Create a Redfish Client at the ip address given
        and login with the give user, password.
        """

        if BootpxePlugin._is_cloud_env():
            redfish_tool = imp.load_source('redfishtool', _CLOUD_REDFISH_PATH)
            redfish_obj = redfish_tool.RedfishClient(base_url=ipaddr,
                username=user, password=pwd, default_prefix='/redfish/v1')
        else:
            redfish_obj = redfish.redfish_client(base_url='https://' + ipaddr,
                username=user, password=pwd, default_prefix='/redfish/v1')

        redfish_obj.login()
        return redfish_obj

    def _is_new_bmc_user(self, node):
        """
        Returns True if new iLO user being added to LITP model,
        False otherwise
        """

        return node.system.bmc.is_updated() and \
            node.system.bmc.username != \
              node.system.bmc.applied_properties.get('username', None)

    def create_configuration(self, plugin_api_context):
        """
        Creates the tasks to pxe boot a node

        .. code-block:: bash
            :linenos:

            litp create -t blade -p /infrastructure/systems/sys \
-o system_name=ABC00000A0

            litp create -t bmc -p /infrastructure/systems/sys/bmc \
-o ipaddress=10.10.10.10 username=root password_key=key-for-root

            litp inherit -p /deployments/d1/clusters/c1/nodes/n1/system \
-s /infrastructure/systems/sys

        Note that a valid username and password_key must be created
        with litpcrypt tool, before trying to use them in the model.
        Use ``litpcrypt -h`` for more information.

        *An example of XML for bootpxe configuration:*

        .. code-block:: xml

            <litp:blade id="sys">
              <system_name>ABC00000A0</system_name>
              <litp:bmc id="bmc">
                <ipaddress>10.10.10.10</ipaddress>
                <username>root</username>
                <password_key>key-for-root</password_key>
              </litp:bmc>
            </litp:blade>
        """

        tasks = []

        nodes = plugin_api_context.query('node')

        nodes_lst = [
            node
            for node in nodes
            if node.system and hasattr(node.system, 'bmc') and
                 node.system.bmc is not None
        ]
        # TORF-538735
        for node in [n for n in nodes_lst if self._is_new_bmc_user(n)]:

            the_bmc = node.system.bmc

            cbt = CallbackTask(
                the_bmc,
                'Update iLO user "%s"' % node.hostname,
                self._update_username_property,
                node.hostname,
                the_bmc.username,
                tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG
            )
            tasks.append(cbt)

        for node in [n for n in nodes_lst if n.system.is_initial()]:

            the_bmc = node.system.bmc

            cbt = CallbackTask(
                node.system.bmc,
                'PXE boot node "%s"' % node.hostname,
                self._exec_pxeboot_request,
                node.hostname,
                the_bmc.ipaddress,
                the_bmc.username,
                the_bmc.password_key,
                tag_name=deployment_plan_tags.BOOT_TAG
            )
            tasks.append(cbt)

        return tasks

    def _update_username_property(self, callback_api, hostname, user):
        """
        The Callback function that logs the change of the username occurred.
        This method is a stub and exists only for the plan to execute and set
        the model item to Applied state.

        :param callback_api: Callback API context reference
        :type  callback_api: CallbackApi
        :param str hostname: Hostname of the node being controlled
        :param str user: Username to access node's BMC
        """

        preamble = '._update_username_property %s ' % callback_api + \
             hostname + ':'

        _LOG.trace.debug(
            preamble +
            '----------------------------- ' +
            'updating iLO user to %s for %s ' % (user, hostname) +
            '------------------------------'
        )

    def _exec_pxeboot_request(self, callback_api, hostname, ipaddr,
                              user, pkey):
        """
        The Callback function, executed by the Execution Manager
        on the MS to actually carry out the PXE boot request

        :param callback_api: Callback API context reference
        :type  callback_api: CallbackApi
        :param str hostname: Hostname of the node being controlled
        :param str ipaddr: IP address of node's BMC
        :param str user: Username to access node's BMC
        :param str pkey: Password key used to retrieve password to
                         authenticate to node's BMC
        """

        preamble = '._exec_pxeboot_request: ' + hostname + ' : '

        _LOG.trace.debug(preamble +
                         '----------------------------- ' +
                         '_exec_pxeboot_request: Start ' +
                         '------------------------------')

        _LOG.trace.debug((preamble +
                          "Will create session with Redfish API at %s " +
                          "using %s/%s") %
                         (ipaddr, user, pkey))

        password = self._get_password(callback_api, user, pkey)
        if not password:
            msg = "No password available from keyring for '%s'" % pkey
            _LOG.trace.debug(preamble + msg)
            raise CallbackExecutionException(msg)
        else:
            try:
                try:
                    redfish_obj = self._login(ipaddr, user, password)
                except InvalidCredentialsError as excep:
                    msg = "Invalid credentials provided for BMC"
                    _LOG.trace.debug(preamble + msg)
                    raise CallbackExecutionException(excep)

                self._toggle_power(redfish_obj, "ForceOff")
                self._sleep_and_check_plan_state(callback_api, hostname, 30)
                self._set_pxe(redfish_obj)
                self._sleep_and_check_plan_state(callback_api, hostname, 15)
                self._toggle_power(redfish_obj, "On")
                self._sleep_and_check_plan_state(callback_api, hostname, 90)

                try:
                    redfish_obj.logout()
                except BadRequestError as excep:
                    _LOG.trace.debug(preamble + str(excep))

            except RetriesExhaustedError:
                error_msg = preamble + "Max number of retries exhausted"
                _LOG.trace.debug(error_msg)
                raise CallbackExecutionException(error_msg)

            except DecompressResponseError:
                error_msg = preamble + "Error while decompressing response"
                _LOG.trace.debug(error_msg)
                raise CallbackExecutionException(error_msg)

        _LOG.trace.debug(preamble +
                         '----------------------------- ' +
                         '_exec_pxeboot_request: End ' +
                         '------------------------------')

    def _toggle_power(self, redfish_object, reset_type):
        """
        Toggle power on the node.
        :param redfish_object: redfish client object
        :param reset_type: value to be set for ResetType parameter in the body
        """
        preamble = '._toggle_power: '
        body = {"ResetType": reset_type}
        response = redfish_object.post(
            "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/",
            body=body)

        if response.status == 200:
            _LOG.trace.debug(preamble + "Power {0} Outcome: Success"
                             .format(reset_type))
        else:
            error = BootpxePlugin.get_error_message(response)
            if response.status == 400 and \
                    'InvalidOperationForSystemState' in error:
                msg = "Power {0} Outcome: system is already in power {0} " \
                      "state".format(reset_type)
                _LOG.trace.debug(preamble + msg)
            else:
                msg = "Power {0} Outcome: Failure, status:{1} : '{2}'".format(
                    reset_type, response.status, error)
                _LOG.trace.debug(preamble + msg)
                raise CallbackExecutionException(msg)

    def _set_pxe(self, redfish_object):
        """
        Set boot device to PXE.
        :param redfish_object: redfish client object
        """
        preamble = '._set_pxe: '

        body = {"Boot": {"BootSourceOverrideTarget": "Pxe",
                         "BootSourceOverrideEnabled": "Once"}}
        response = redfish_object.patch("/redfish/v1/Systems/1/", body=body)

        if response.status == 200:
            _LOG.trace.debug(preamble + "Set boot to pxe Outcome: Success")
        else:
            error = BootpxePlugin.get_error_message(response)
            msg = "Set boot to pxe Outcome: Failure, status:{0} : '{1}'" \
                .format(response.status, error)
            _LOG.trace.debug(preamble + msg)
            raise CallbackExecutionException(msg)

    @staticmethod
    def get_error_message(response):
        """
        Extracts error message from given response object
        :param response: Response from redfish rest APIs
        """
        try:
            response_dict = response.dict
            extended_info = response_dict["error"]["@Message.ExtendedInfo"][0]
            if "Message" in extended_info:
                message = str(extended_info["Message"])
            else:
                if "MessageId" in extended_info:
                    message = str(extended_info["MessageId"])
                else:
                    message = str(extended_info["MessageID"])
            return message
        except (KeyError, ValueError):
            return response

    def validate_model(self, plugin_api_context):
        """
        Validates the Model for unique IP addresses for BMCs
        and that a password is set for each password_key used.
        """

        errors = []

        bmcs = [node.system.bmc for node in plugin_api_context.query('node')
                if hasattr(node.system, 'bmc') and node.system.bmc is not None]

        errors.extend(BootpxePlugin._validate_model_bmc_ipaddress(bmcs))

        return errors

    @staticmethod
    def _validate_model_bmc_ipaddress(bmcs):
        """
        Validates that every BMC instance in the Model uses unique IP address.
        """
        errors = []

        for bmc in bmcs:
            ipaddresses = [item.ipaddress for item in bmcs if item != bmc]
            if bmc.ipaddress in ipaddresses:
                msg = ("Property 'ipaddress' has value " +
                       "'%s' that is not unique in " +
                       "the Model.") % bmc.ipaddress
                err = ValidationError(item_path=bmc.get_vpath(),
                                      property_name='ipaddress',
                                      error_message=msg)
                errors.append(err)

        return errors

    def _sleep_and_check_plan_state(self, callback_api, hostname, sleep):
        """
        Function used to sleep the process while each pxeboot action
        executes

        :param callback_api: Callback API context reference
        :type  callback_api: CallbackApi
        :param str hostname: Hostname of the node being controlled
        :param int sleep: amount of time to sleep
        """
        if not sleep:
            return None

        preamble = '._sleep_and_check_plan_state: '

        interval = 1.0 if sleep >= 1 else sleep
        timeout = Timeout(sleep)

        while not timeout.has_elapsed():
            if not callback_api.is_running():
                raise PlanStoppedException(
                    "Plan execution has been stopped.")
            timeout.sleep(interval)
            elapsed_time = timeout.get_elapsed_time()
            _LOG.trace.debug((preamble +
                              'Waiting for state transition to end. ' +
                              '{0} second(s) elapsed out of {1} ' +
                              'second(s) on node "{2}".')
                             .format(int(elapsed_time), int(sleep), hostname))
        return None

    def get_security_credentials(self, plugin_api_context):
        """
        Registers pairs of credentials for bmc.username" and bmc.password_key
        required by the plugin for each ``bmc`` type in the model.

        :param plugin_api_context: PluginApiContext instance to access Model
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext

        :returns: A list of credentials pairs (bmc.username, bmc.password_key)
        :rtype: list
        """
        bmcs = [node.system.bmc for node in plugin_api_context.query('node')
                if hasattr(node.system, 'bmc') and node.system.bmc is not None]

        credentials = []
        for bmc in bmcs:
            credentials.append((bmc.username, bmc.password_key))
        return credentials
