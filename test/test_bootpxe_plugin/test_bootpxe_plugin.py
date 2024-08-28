##############################################################################
# COPYRIGHT Ericsson AB 2020
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import mock
import unittest
from mock import MagicMock, patch
import json
import os
import sys

from redfish.rest.v1 import BadRequestError, InvalidCredentialsError, DecompressResponseError, RetriesExhaustedError

from litp.extensions.core_extension import CoreExtension
from litp.core.model_manager import ModelManager
from litp.core.plugin_manager import PluginManager
from litp.core.plugin_context_api import PluginApiContext
from litp.core.validators import ValidationError
from bmc_extension.bmc_extension import BmcExtension
from litp.core.execution_manager import (CallbackExecutionException,
                                         PlanStoppedException)
from litp.plan_types.deployment_plan import deployment_plan_tags
from bootpxe_plugin.bootpxe_plugin import BootpxePlugin

# Common constants
SYS1 = '/infrastructure/systems/sys1'
SYS2 = '/infrastructure/systems/sys2'
BMC1 = '/infrastructure/systems/sys1/bmc'
BMC2 = '/infrastructure/systems/sys2/bmc'


class TestHelper(object):

    @staticmethod
    def read_data(filename):
        """
        open the file and reads data from
        the path specified in the arguments
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
        path = os.path.join(os.path.join(parent_dir, 'resources'), filename)
        with open(path, 'r') as f:
            return f.read()

    @staticmethod
    def get_mock_response(response_status, resource_text):
        """
        set the response with the provided arguments
        and return mocked response
        """
        response = MagicMock()
        response.status = response_status
        response.text = TestHelper.read_data(resource_text)
        if resource_text in ['invalid_parameter_response',
                             'response_with_error_message',
                             'key_error_response',
                             'pxeboot_NoValidSession',
                             'pxeboot_PropertyUnknown',
                             'pxeboot_PropertyValueNotInList',
                             'pxeboot_Success']:
            response.dict = json.loads(response.text)
        return response


class MockCba(object):
    """
    Mock the CallbackApi class
    which offers a Keyring service,
    to fake the get_password() API method
    """
    def get_password(self, service, user):
        return 'secret'

    def do_nothing(self):
        pass


class AnyStringWith(str):
    def __eq__(self, other):
        return self in other


class TestBootpxePlugin(unittest.TestCase):

    exec_preamble = "._exec_pxeboot_request: sc1 : "
    toggle_preamble = '._toggle_power: '
    pxeboot_preamble = "._set_pxe: "
    user_prop_preamble = '._update_username_property'

    def setUp(self):
        """
        Construct a model, sufficient for test cases
        that you wish to implement in this suite.
        """
        self.model = ModelManager()
        # Instantiate a plugin API context to pass to plugin
        self.context = PluginApiContext(self.model)
        self.plugin_manager = PluginManager(self.model)
        # Use add_property_types to add property types defined in
        # model extenstions
        # For example, from CoreExtensions (recommended)
        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())

        # Use add_item_types to add item types defined in
        # model extensions
        # For example, from CoreExtensions
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())

        # Add default minimal model (which creates '/' root item)
        self.plugin_manager.add_default_model()

        self.extension = BmcExtension()
        self.plugin_manager.add_property_types(
            self.extension.define_property_types())
        self.plugin_manager.add_item_types(self.extension.define_item_types())

        # Instantiate your plugin and register with PluginManager
        self.plugin = BootpxePlugin()

    def setup_model(self):
        # Use ModelManager.crete_item and ModelManager.create_inherited
        # to create and inherit items in the model.
        self.model.create_item('deployment', '/deployments/d1')
        self.model.create_item('cluster', '/deployments/d1/clusters/c1')
        self.node1 = self.model.create_item("node",
                                            '/deployments/d1/clusters/c1/nodes/n1', hostname="node1")
        self.node1 = self.model.create_item("node",
                                            '/deployments/d1/clusters/c1/nodes/n2', hostname="special")

    def test_validate_bmc_ipaddress_not_unique(self):
        """
        Two BMCs sharing the same IPAddress - non-unique IPs
        """

        self._create_standard_items()

        # Add two non unique bmc items
        self.model.create_item('bmc',
                               BMC1,
                               ipaddress='10.23.23.23',
                               username='admin',
                               password_key='key-for-root')
        self.model.create_item('blade',
                               SYS2,
                               serial='deadbeef',
                               system_name='MySys2')
        self.model.create_item('bmc',
                               BMC2,
                               ipaddress='10.23.23.23',
                               username='admin',
                               password_key='key-for-me')

        nodes_url = '/deployments/d1/clusters/c1/nodes/'

        self.model.create_item('node',
                               nodes_url + 'n2',
                               hostname='node2')
        self.model.create_inherited(SYS2, nodes_url + 'n2/system')

        bmcs = [node.system.bmc for node in self.context.query('node')]

        errors = self.plugin._validate_model_bmc_ipaddress(bmcs)
        errors_expected = []
        emsg = "Property 'ipaddress' has value '10.23.23.23' that " + \
               "is not unique in the Model."
        for node in ['n1', 'n2']:
            err = ValidationError(item_path=nodes_url + node + '/system/bmc',
                                  property_name='ipaddress',
                                  error_message=emsg)
            errors_expected.append(err)

        self.assertEqual(set(errors_expected), set(errors))
        self.assertEqual(type(errors_expected), type(errors))

    def test_validate_model(self):
        """
        Multiple errors from invalid Model
        """

        self._create_standard_items()

        # Add two non unique bmc items
        self.model.create_item('bmc',
                               BMC1,
                               ipaddress='10.23.23.23',
                               username='admin',
                               password_key='foo')
        self.model.create_item('blade',
                               SYS2,
                               serial='deadbeef',
                               system_name='MySys2')
        self.model.create_item('bmc',
                               BMC2,
                               ipaddress='10.23.23.23',
                               username='admin',
                               password_key='bazfoo')

        nodes_url = '/deployments/d1/clusters/c1/nodes/'
        self.model.create_item('node',
                               nodes_url + 'n2',
                               hostname='node2')
        self.model.create_inherited(SYS2, nodes_url + 'n2/system')
        self.context.get_password = lambda s, u: None

        errors = self.plugin.validate_model(self.context)

        emsg = "Property 'ipaddress' has value '10.23.23.23' " + \
               "that is not unique in the Model."
        err_b1 = ValidationError(item_path=nodes_url + 'n1/system/bmc',
                                 property_name='ipaddress',
                                 error_message=emsg)

        err_b2 = ValidationError(item_path=nodes_url + 'n2/system/bmc',
                                 property_name='ipaddress',
                                 error_message=emsg)

        errors_expected = [err_b1, err_b2]

        self.assertEqual(set(errors_expected), set(errors))
        self.assertEqual(type(errors_expected), type(errors))

    def _create_standard_items(self, sys_type='blade'):
        self.model.create_root_item('root', '/')

        deploy_url = '/deployments/d1'
        cluster_url = deploy_url + '/clusters/c1'
        nodes_url = cluster_url + '/nodes'

        rsp1 = self.model.create_item(sys_type,
                                      SYS1,
                                      serial='abcd1234',
                                      system_name='System1')
        rsp2 = self.model.create_item('deployment', deploy_url)
        rsp3 = self.model.create_item('cluster', cluster_url)
        rsp4 = self.model.create_item('node',
                                      nodes_url + '/n1',
                                      hostname='sc1')
        rsp5 = self.model.create_inherited(SYS1, nodes_url + '/n1/system')

        for rsp in [rsp1, rsp2, rsp3, rsp4, rsp5]:
            self.assertFalse(isinstance(rsp, list),
                             "Errors creating Model Item: %s" % rsp)

    def _mock_pxe_boot_tasks(self):
        self.plugin._set_pxe = MagicMock()
        self.plugin._sleep_and_check_plan_state = MagicMock()
        self.plugin._toggle_power = MagicMock()

    @patch('redfish.rest.v1.HttpClient')
    def test_callback_method_01_valid_login(self, rf_client_patch):
        """
        login attempt with valid login to exercise the login code
        """
        rf_client_instance_mock = MagicMock()
        self._mock_pxe_boot_tasks()
        rf_client_patch.return_value = rf_client_instance_mock

        self.plugin._exec_pxeboot_request(MockCba(), 'sc1', '9.8.7.6',
                                          'bob', 'key-for-root')

        self.assertTrue(rf_client_instance_mock.login.called)
        self.assertTrue(rf_client_instance_mock.logout.called)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    def test_callback_method_02_no_password(self, log_patch):
        """
        Replacement method that fails to retrieve a Password,
        to exercise the code that handles Password retrieval failure.
        """
        self.plugin._get_password = lambda c, u, k: None

        self.assertRaises(CallbackExecutionException,
                          self.plugin._exec_pxeboot_request,
                          MockCba(), 'sc1', '9.8.7.6',
                          'bob', 'key-for-root')

        log_patch.trace.debug.assert_called_with(
            self.exec_preamble + "No password available from keyring for 'key-for-root'")

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_callback_method_03_login_incorrect_password(self, rf_client_patch, log_patch):
        """
        Login attempt using incorrect password,
        to exercise the code that handles invalid credentials exception.
        """
        rf_client_instance_mock = MagicMock()
        rf_client_instance_mock.login.side_effect = InvalidCredentialsError
        rf_client_patch.return_value = rf_client_instance_mock

        self.assertRaises(CallbackExecutionException,
                          self.plugin._exec_pxeboot_request,
                          MockCba(), 'sc1', '9.8.7.6',
                          'bob', 'key-for-root')
        log_patch.trace.debug.assert_called_with(self.exec_preamble + "Invalid credentials provided for BMC")

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_callback_method_04_retries_exhausted_error(self, rf_client_patch, log_patch):
        """
        Login attempt where redfish raises RetriesExhaustedError,
        to exercise the code that handles this exception.
        """
        excep_msg = "Max number of retries exhausted"
        rf_client_instance_mock = MagicMock()
        rf_client_instance_mock.login.side_effect = RetriesExhaustedError(excep_msg)
        rf_client_patch.return_value = rf_client_instance_mock

        self.assertRaises(CallbackExecutionException,
                          self.plugin._exec_pxeboot_request,
                          MockCba(), 'sc1', '9.8.7.6',
                          'bob', 'key-for-root')
        log_patch.trace.debug.assert_called_with(self.exec_preamble + excep_msg)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_callback_method_05_decompress_respose_error(self, rf_client_patch, log_patch):
        """
        Login attempt where redfish raises DecompressResponseError,
        to exercise the code that handles this exception.
        """
        excep_msg = "Error while decompressing response"
        rf_client_instance_mock = MagicMock()
        rf_client_instance_mock.login.side_effect = DecompressResponseError(excep_msg)
        rf_client_patch.return_value = rf_client_instance_mock

        self.assertRaises(CallbackExecutionException,
                          self.plugin._exec_pxeboot_request,
                          MockCba(), 'sc1', '9.8.7.6',
                          'bob', 'key-for-root')
        log_patch.trace.debug.assert_called_with(self.exec_preamble + excep_msg)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_callback_method_06_logout_bad_request(self, rf_client_patch, log_patch):
        """
        Logout attempt where incorrect session details are provided,
        to exercise the code that handles bad request exception.
        """
        excep_msg = "Bad request error. Invalid session resource"
        rf_client_instance_mock = MagicMock()
        self._mock_pxe_boot_tasks()
        rf_client_instance_mock.logout.side_effect = BadRequestError(excep_msg)
        rf_client_patch.return_value = rf_client_instance_mock

        self.plugin._exec_pxeboot_request(MockCba(), 'sc1', '9.8.7.6', 'bob', 'key-for-root')
        log_patch.trace.debug.assert_any_call(self.exec_preamble + excep_msg)

    def test_create_configuration_01_valid_BMC_with_call_back_task(self):
        """
        With a valid BMC, just 1 CallbackTask is expected
        """

        self._create_standard_items()
        self.model.create_item('bmc',
                               '/infrastructure/systems/sys1/bmc',
                               ipaddress='9.8.7.6',
                               username='bob',
                               password_key='key-for-root')

        tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(1, len(tasks))
        self.assertEqual(deployment_plan_tags.BOOT_TAG, tasks[0].tag_name)
        self.assertEqual(('sc1', '9.8.7.6', 'bob', 'key-for-root'), tasks[0].args)

    def test_create_configuration_02_no_BMC_no_call_back_task(self):
        """
        A valid Blade System - but without a BMC - no Task expected
        """

        self._create_standard_items()

        tasks = self.plugin.create_configuration(self.context)

        self.assertEqual(0, len(tasks))

    def test_create_configuration_03_vanilla_system_no_call_back_task(self):
        """
        With a vanilla System - without a BMC - no Task expected
        """

        self._create_standard_items('system')

        tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(0, len(tasks))

    def test_update_bmc_username_property_call_back_task(self):
        """
        Ensure username property is updatabale and task is generated to
        update it
        """

        infra_bmc_url = '/infrastructure/systems/sys1/bmc'
        deploy_infra_url = '/deployments/d1/clusters/c1/nodes/n1/system/bmc'

        self._create_standard_items()
        self.model.create_item('bmc',
                               infra_bmc_url,
                               ipaddress='9.8.7.6',
                               username='bob',
                               password_key='key-for-bob')
        self.model.create_inherited(infra_bmc_url, deploy_infra_url)
        self.model.set_all_applied()
        self.model.update_item(infra_bmc_url,username='not_bob')
        self.assertEqual(
            'Updated',
            self.model.query_by_vpath(infra_bmc_url).get_state())
        self.assertEqual(
            'Updated',
            self.model.query_by_vpath(deploy_infra_url).get_state())
        tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(1, len(tasks))
        self.assertEqual(deployment_plan_tags.PRE_NODE_CLUSTER_TAG, tasks[0].tag_name)
        self.assertEqual(('sc1', 'not_bob'), tasks[0].args)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    def test_update_username_call_back_task_execution(self, log_patch):
        """
        Tests that debug message is logged when CallbackTask is executed
        """

        self.plugin._update_username_property(MockCba(), 'sc1', 'bob')
        log_patch.trace.debug.assert_called_with(AnyStringWith(self.user_prop_preamble))

    @mock.patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @mock.patch('redfish.rest.v1.HttpClient')
    def test_toggle_power_successful_poweron(self, mock_redfish, log_mock):
        """
        Validating the toggle power functionality in a positive
        workflow when all the arguments are provided correctly
        """
        mock_redfish.post.return_value = TestHelper. \
            get_mock_response(200, 'success_response')
        self.plugin._toggle_power(mock_redfish, "On")
        log_mock.trace.debug.assert_called_with(self.toggle_preamble +
                                                "Power On Outcome: Success")

    @mock.patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @mock.patch('redfish.rest.v1.HttpClient')
    def test_toggle_power_invalid_parameter(self, mock_redfish, log_mock):
        """
        Validating the toggle power functionality when an invalid
        parameter is passed as an argument
        """
        mock_redfish.post.return_value = TestHelper. \
            get_mock_response(400, 'invalid_parameter_response')
        self.assertRaises(CallbackExecutionException,
                          self.plugin._toggle_power, mock_redfish, "On")
        log_mock.trace.debug.assert_called_with(self.toggle_preamble +
                                                "Power On Outcome: Failure,"
                                                " status:400 :"
                                                " 'Base.1.0."
                                                "ActionNotSupported'")

    @mock.patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @mock.patch('redfish.rest.v1.HttpClient')
    def test_toggle_power_invalid_session(self, mock_redfish, log_mock):
        """
        Validating the toggle power functionality when a session
        becomes invalid
        """
        mock_redfish.post.return_value = TestHelper. \
            get_mock_response(401, 'invalid_parameter_response')
        self.assertRaises(CallbackExecutionException,
                          self.plugin._toggle_power, mock_redfish, "On")
        log_mock.trace.debug.assert_called_with(self.toggle_preamble +
                                                "Power On Outcome: Failure,"
                                                " status:401 :"
                                                " 'Base.1.0."
                                                "ActionNotSupported'")

    def test_get_error_message_with_id(self):
        """
        Validating the get_error_message functionality when the response
        object contains only message id
        """
        response = TestHelper.get_mock_response(401,
                                                'invalid_parameter_response')
        message = self.plugin.get_error_message(response)
        self.assertEqual(message, "Base.1.0.ActionNotSupported")

    def test_get_error_message_with_message(self):
        """
        Validating the get_error_message functionality when the response
        object contains the actual message
        """
        response = TestHelper.get_mock_response(401,
                                                'response_with_error_message')
        message = self.plugin.get_error_message(response)
        self.assertEqual(message, "Base Action Not Supported")

    def test_key_error_message(self):
        """
        Validating the get_error_message functionality when the response
        object is returned as it is
        """
        response = TestHelper.get_mock_response(401, 'key_error_response')
        message = self.plugin.get_error_message(response)
        self.assertEqual(message, response)

    def test_sleep_and_check_plan_state(self):
        callback_api = mock.Mock()
        callback_api.is_running = lambda: False

        hostname = 'node1'

        # should exit with None
        for sleep in [0, 0.0]:
            self.assertEqual(None,
                             self.plugin._sleep_and_check_plan_state(
                                 callback_api, hostname, sleep))
            # should exit with exception
        for sleep in [0.1, 0.9, 1, 1.0, 10]:
            self.assertRaises(PlanStoppedException,
                              self.plugin._sleep_and_check_plan_state,
                              callback_api, hostname, sleep)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_pxeboot_success(self, mock_redfish, log_patch):
        """
        Validating the PXE Boot functionality in a positive
        workflow when all the arguments are provided correctly
        """
        mock_redfish.patch.return_value = \
            TestHelper.get_mock_response(200, 'pxeboot_Success')
        msg = "Set boot to pxe Outcome: Success"

        self.plugin._set_pxe(mock_redfish)
        log_patch.trace.debug.assert_called_with(self.pxeboot_preamble + msg)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_pxeboot_invalid_session(self, mock_redfish, log_patch):
        """
        Validating the PXE Boot functionality in a negative
        workflow with an invalid session
        """
        response = TestHelper.get_mock_response(401, 'pxeboot_NoValidSession')
        response.login.side_effect = InvalidCredentialsError
        mock_redfish.patch.return_value = response
        msg = "Set boot to pxe Outcome: Failure, status:401 : " \
              "'Base.0.10.NoValidSession'"

        self.assertRaises(CallbackExecutionException,
                          self.plugin._set_pxe, mock_redfish)
        log_patch.trace.debug.assert_called_with(self.pxeboot_preamble + msg)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_pxeboot_property_unknown(self, mock_redfish, log_patch):
        """
        Validating the PXE Boot functionality in a negative
        workflow with a unknown property
        """
        mock_redfish.patch.return_value = \
            TestHelper.get_mock_response(400, 'pxeboot_PropertyUnknown')
        msg = "Set boot to pxe Outcome: Failure, status:400 : " \
              "'Base.0.10.PropertyUnknown'"

        self.assertRaises(CallbackExecutionException,
                          self.plugin._set_pxe, mock_redfish)
        log_patch.trace.debug.assert_called_with(self.pxeboot_preamble + msg)

    @patch('bootpxe_plugin.bootpxe_plugin._LOG')
    @patch('redfish.rest.v1.HttpClient')
    def test_pxeboot_invalid_property_value(self, mock_redfish, log_patch):
        """
        Validating the PXE Boot functionality in a positive
        workflow with an invalid property value
        """
        mock_redfish.patch.return_value = \
            TestHelper.get_mock_response(400, 'pxeboot_PropertyValueNotInList')
        msg = "Set boot to pxe Outcome: Failure, status:400 : " \
              "'Base.0.10.PropertyValueNotInList'"

        self.assertRaises(CallbackExecutionException,
                          self.plugin._set_pxe, mock_redfish)
        log_patch.trace.debug.assert_called_with(self.pxeboot_preamble + msg)

    def test_get_security_credentials(self):
        empty_creds = self.plugin.get_security_credentials(self.context)
        self.assertEqual([], empty_creds)

        self._create_standard_items()
        self.model.create_item('bmc', BMC1, ipaddress='9.8.7.6',
                               username='bob', password_key='key-for-root')

        creds = self.plugin.get_security_credentials(self.context)
        self.assertEqual([('bob', 'key-for-root')], creds)

    @patch('os.path')
    def test_redfish_no_cloud_tool(self, mock_os_path):
        """
        Validating when Redfish tool path file does not exist.
        """
        mock_os_path.isfile.return_value = False
        self.assertFalse(BootpxePlugin._is_cloud_env())

    @patch('os.access')
    @patch('os.path')
    def test_redfish_cloud_tool_no_exec(self, mock_os_path, mock_access):
        """
        Validating when Redfish tool path file exist but is not accessible.
        """
        mock_os_path.isfile.return_value = True
        mock_access.return_value = False
        self.assertFalse(BootpxePlugin._is_cloud_env())

    @patch('os.path')
    @patch('os.access')
    def test_redfish_cloud_tool_exec(self, mock_os_path, mock_access):
        """
        Validating when Redfish tool path file exist and is accessible.
        """
        mock_os_path.isfile.return_value = True
        mock_access.return_value = True
        self.assertTrue(BootpxePlugin._is_cloud_env())

    @patch('os.path')
    def test_redfish_cloud_tool_exception(self, mock_os_path):
        """
        Validating when Redfish tool path resource thrown an exception.
        """
        mock_os_path.isfile.side_effect = OSError
        self.assertFalse(BootpxePlugin._is_cloud_env())

    @patch('os.path')
    @patch('os.access')
    def test_redfish_cloud_adapter(self, mock_os_path, mock_access):
        """
        Validating cloud adapter invocation
        """
        mock_os_path.isfile.return_value = True
        mock_access.return_value = True
        self.assertTrue(BootpxePlugin._is_cloud_env())

        sys.modules['redfishtool'] = MagicMock()

        with patch('imp.load_source') as module:
            cloud_adapter_mock = MagicMock()
            module.return_value = cloud_adapter_mock
            self._mock_pxe_boot_tasks()

            self.plugin._exec_pxeboot_request(MockCba(), 'sc1', '9.8.7.6',
                                              'bob', 'key-for-root')

            self.assertTrue(module.called)
            self.assertTrue(cloud_adapter_mock.RedfishClient().login.called)
            self.assertTrue(cloud_adapter_mock.RedfishClient().logout.called)
