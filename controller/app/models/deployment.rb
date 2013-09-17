##
# @api model

# 
# @!attribute [r] state
#   @return [String] The state of deployment. i.e. active..
# @!attribute [r] created_at
#   @return [Date] Timestamp of when the deployment was created
# @!attribute [r] hot_deploy
#   @return [Boolean]
# @!attribute [r] force_clean_build
#   @return [Boolean]
# @!attribute [r] ref
#   @return [String] The git ref to be used for this deployment
# @!attribute [r] artifact_url
#   @return [String] The URL where the deployment artifact can be downloaded from.

class Deployment
  include Mongoid::Document
  embedded_in :application

  self.field :deployment_id, type: String
  self.field :created_at,type: Date
  self.field :state, type: String, default: "active"
  self.field :hot_deploy, type: Boolean, default: false
  self.field :force_clean_build, type: Boolean, default: false
  self.field :ref, type: String
  self.field :artifact_url, type: String

  #TODO define possible values?
  DEPLOYMENT_STATES =[:active, :past, :prepared]

  validates :state, :inclusion => { :in => DEPLOYMENT_STATES.map { |s| s.to_s }, :message => "%{value} is not a valid state. Valid states are #{DEPLOYMENT_STATES.join(", ")}." }
  validates :ref, :allow_blank => true, length: {maximum: 256}
  validate  :validate_deployment

  def validate_deployment
    if self.ref and self.artifact_url
      self.errors[:base] << "You can either use an aritifact URL or ref.  You can not use both."
    end
  end
  #TODO add error codes for deployment to li/misc/docs/ERROR_CODES.txt
  def self.validation_map
    return {}
  end
  ##
  # Returns the deployment object as a hash
  # @return [Hash]
  def to_hash
    {
      "deployment_id" => deployment_id, "created_at" => created_at, "state" => state, "hot_deploy" => hot_deploy,
      "force_clean_build" => force_clean_build, "ref" => ref, "artifact_url" => artifact_url
      }
  end
end
