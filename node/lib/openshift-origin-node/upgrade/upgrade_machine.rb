#!/bin/env ruby
require 'state_machine'
require 'stomp'
require 'mongoid'
require 'json'

require_relative 'cluster_scanner'

module OpenShift
  module Runtime
    module Upgrade
      class StompClient
        def self.instance
          @@instance ||= create_instance
        end

        def self.create_instance
          opts = { hosts: [ { login: "mcollective", passcode: "marionette", host: "localhost", port: 6163 } ] }
          Stomp::Client.new(opts)
        end
      end

      class UpgradeExecution
        include Mongoid::Document
        include Mongoid::Timestamps

        store_in collection: "upgrade_executions"

        field :target_version, type: String
        field :state, type: String
        
        has_many :gear_machines
      end

      class GearMachine
        include Mongoid::Document
        include Mongoid::Timestamps

        store_in collection: "upgrade_gear_machines"

        field :uuid, type: String
        field :node, type: String
        field :namespace, type: String
        field :target_version, type: String
        field :active, type: Boolean, default: true
        field :num_attempts, type: Integer, default: 0
        field :max_attempts, type: Integer
        
        embeds_many :upgrade_results, :order => :created_at.desc
        belongs_to :upgrade_execution

        state_machine :state, :initial => :new do
          before_transition any => :upgrading, :do => :queue_upgrade

          event :upgrade do
            transition :new => :upgrading
          end

          event :complete_upgrade do
            transition :upgrading => :complete, :if => lambda {|gear| gear.upgrade_results.last.successful? }
            transition :upgrading => same, :if => lambda {|gear| gear.upgrade_results.last.failed? && gear.num_attempts < gear.max_attempts }
            transition :upgrading => :failed
          end
        end

        def queue_upgrade
          self.num_attempts += 1

          puts "queueing upgrade for #{self.uuid} [#{self.active ? 'active' : 'inactive'}] (attempt #{self.num_attempts} of #{self.max_attempts})"
          
          msg = {
            uuid: self.uuid,
            namespace: self.namespace,
            node: self.node,
            ignore_cartridge_version: true,
            target_version: self.target_version,
            attempt: self.num_attempts
          }

          StompClient.instance.publish "mcollective.upgrade.node.#{self.node}", JSON.dump(msg)
        end

        def complete_upgrade(result = nil, *args)
          raise "Result is required" unless result

          self.upgrade_results << result
          super
        end
      end

      class UpgradeResult
        include Mongoid::Document
        include Mongoid::Timestamps

        field :upgrade_errors, type: Array, default: []
        field :gear_upgrader_result, type: Hash

        embedded_in :gear_machine

        def successful?
          self.upgrade_errors.empty? && self.gear_upgrader_result && self.gear_upgrader_result['upgrade_complete']
        end

        def failed?
          !successful?
        end
      end     

      class Coordinator
        include ClusterScanner

        def initialize
        end

        def upgrade(execution)
          gear_machines = GearMachine.where(upgrade_execution_id: execution.id).order_by(:active.desc)
          gear_machines.each do |gear|
            gear.upgrade if gear.can_upgrade?
          end

          num_remaining = GearMachine.where(upgrade_execution_id: execution.id, :state.in => [:new, :upgrading]).count

          if num_remaining == 0
            puts "No remaining incomplete gears; exiting"
            return
          end

          puts "Remaining machines: #{num_remaining}"

          StompClient.instance.subscribe("mcollective.upgrade.results", {:ack => "client" }) do |msg|
            begin
              remote_result = JSON.load(msg.body)
              gear_uuid = remote_result["uuid"]

              gear = GearMachine.find_by(uuid: gear_uuid)

              if gear
                result = UpgradeResult.new(gear_upgrader_result: remote_result['gear_upgrader_result'])
                gear.complete_upgrade(result)
                puts "Processed reply for gear #{gear_uuid}"
              else
                puts "Dropping result for missing gear #{gear_uuid}"
              end

              StompClient.instance.acknowledge(msg)
            rescue => e
              puts e.message
              puts e.backtrace.join("\n")
            end
          end

          print "Waiting for gear replies..."
          loop do
            num_remaining = GearMachine.where(upgrade_execution_id: execution.id, :state.in => [:new, :upgrading]).count
            
            sleep 1

            print "."
            $stdout.flush
          end
        end

        def create_execution(target_version, max_attempts)
          execution = UpgradeExecution.find_by(target_version: target_version)

          if execution
            puts "Reusing existing execution for version #{target_version}"
          else
            puts "Creating new execution for version #{target_version}"

            execution = UpgradeExecution.create(target_version: target_version)

            find_gears_to_upgrade.each do |gear|
              execution.gear_machines << GearMachine.create(uuid: gear[:uuid], node: gear[:node], target_version: target_version, 
                max_attempts: max_attempts, active: gear[:active], namespace: gear[:namespace])
            end
          end

          execution
        end
      end
    end
  end
end

Mongoid.load!("mongoid.yml")

include OpenShift::Runtime::Upgrade

coord = Coordinator.new

execution = coord.create_execution('2.0.31', 2)

coord.upgrade(execution)
