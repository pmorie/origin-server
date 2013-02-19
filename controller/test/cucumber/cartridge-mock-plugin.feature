@runtime_other
Feature: V2 SDK Mock Plugin Cartridge

  Scenario: Add/Remove mock plugin to/from mock application
  Given a v2 default node
  Given a new mock type application
  When I embed a mock-plugin cartridge into the application
  Then the mock-plugin cartridge private endpoints will be exposed
  And the mock-plugin setup_version marker will exist
  And the mock-plugin setup_failure marker will not exist
  And the mock-plugin MOCK_PLUGIN_EXAMPLE env entry will exist
  And the mock-plugin MOCK_PLUGIN_SERVICE_URL env entry will exist
  When I remove the mock-plugin cartridge from the application
  Then the mock-plugin teardown_called marker will exist
  