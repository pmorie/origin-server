Then /^the mock ([^ ]+) marker should( not)? exist$/ do |marker, negate|
  marker_file = File.join($home_root, @gear.uuid, 'app-root', 'data', '.mock_cartridge_state', marker)

  assert_true (negate ^ File.exists?(marker_file))
end