@runtime
Feature: V2 SDK Mock Cartridge

  Scenario: Add cartridge
  Given a new mock type application
  Then the application git repo will exist
  # And the platform-created default environment variables should exist
  # And the mock cartridge private endpoints should be exposed
  And the mock setup_version marker will exist
  And the mock setup_failure marker will not exist
  And the mock OPENSHIFT_MOCK_EXAMPLE env entry will exist
  And the mock OPENSHIFT_MOCK_SERVICE_URL env entry will exist

  # Scenario: Destroy

  # Scenario: Update application

  # Scenario: Add cartridge w/ user-specified repo

  # Scenario: Start

  # Scenario: Stop

  # Scenario: Move
 
  # Scenario: Tidy

  # Scenario: Access via SSH