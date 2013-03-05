require File.expand_path('../../../test_helper', __FILE__)

class RestApiCartridgeTest < ActiveSupport::TestCase
  include RestApiAuth

  def setup
    with_configured_user
  end

  test 'cartridge scale parameters can be changed' do
    app = with_scalable_app

    carts = app.cartridges.select{ |c| c.scales? }
    assert_equal 1, carts.length

    cart = carts.first
    assert cart.tags.include? :web_framework
    assert cart.scales_from > 0
    assert cart.scales_to != 0
    assert cart.supported_scales_from > 0
    assert_equal(-1, cart.supported_scales_to)

    base = Range.new(cart.supported_scales_from, cart.supported_scales_to == -1 ? User.find(:one, :as => @user).max_gears : [100,cart.supported_scales_to].min).to_a.sample

    name = cart.name

    prefix = cart.prefix_options.dup

    cart.scales_from = base
    cart.scales_to = base

    # The app being used in this test can be being reused from other test cases. When this
    # is the case, a race condition exists that can cause this test to fail with the 
    # 'Application is currently busy' message being tested for in the code below.
    #
    # The following retry logic is a workaround for this race condition.
    # 
    # To attempt to recreate this scenario, you can use the check:app_request_queuing test suite
    # defined in the console Rakefile.
    #
    # This workaround will become unnecessary when the broker is made to queue requests
    # to an application and process them serially.
    #
    # Extra context: The error message is seen in the following files:
    #  controller/app/controllers/applications_controller.rb
    #  controller/app/controllers/app_events_controller.rb
    #  controller/app/controllers/emb_cart_controller.rb
    tries = 0
    
    begin
      tries += 1
      assert cart.save, "Unable to set scales_from/to to #{base}: #{cart.errors.full_messages}"
    rescue Test::Unit::AssertionFailedError => e
      if cart.full_messages.include? 'Application is currently busy performing another operation. Please try again in a minute.'
        retry if tries <= 3
      end

      raise
    end

    assert_equal base, cart.scales_from
    assert_equal base, cart.scales_to

    assert_equal prefix, cart.prefix_options

    cart.reload 

    assert_equal base, cart.scales_from
    assert_equal base, cart.scales_to

  end
end
