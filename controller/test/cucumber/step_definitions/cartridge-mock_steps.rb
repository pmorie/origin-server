Then /^the mock ([^ ]+) marker should( not)? exist$/ do |marker, negate|
  marker_file = File.join($home_root, @gear.uuid, 'app-root', 'data', '.mock_cartridge_state', marker)

  if negate
    assert_file_not_exists marker_file
  else 
    assert_file_exists marker_file
  end
end