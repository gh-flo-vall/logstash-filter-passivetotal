# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Passivetotal < LogStash::Filters::Base

  config_name "passivetotal"
  
  #For apikey and username, report to the page: https://www.passivetotal.org/account_settings 
  config :apikey, :validate => :string, :required => true
  config :username, :validate => :string, :required => true
  config :field, :validate => :string, :required => true
  #Lookup queries: passive,unique,enrichment,malware,osint,subdomains,whois
  config :lookup, :validate => :string, :default => "passive"
  config :target, :validate => :string, :default => "passivetotal"
 

  public
  def register
    require "faraday"
  end # def register

  public
  def filter(event)
  
    unless apikey =~ /^[a-fA-F0-9]{64}$/
      @logger.error("API key must be a 64 character hex string, check: https://www.passivetotal.org/account_settings")
      return
    end

    #Full API documentation: https://api.passivetotal.org/api/docs
    baseurl = "https://api.passivetotal.org/v2/"

    if @lookup == "passive"
      url = "dns/passive"
    elsif @lookup == "unique"
      url = "dns/passive/unique"
    elsif @lookup == "enrichment"
      url = "enrichment" 
    elsif @lookup == "malware"
      url = "enrichment/malware"
    elsif @lookup == "osint"
      url = "enrichment/osint"
    elsif @lookup == "subdomains"
      url = "enrichment/subdomains"
    elsif @lookup == "whois"
      url = "whois"
    end
    
    conn = Faraday.new baseurl
    conn.basic_auth(@username,@apikey)
    begin
      resp = conn.get url do |req|
        req.params[:query] = event.get(@field)
      end
      if resp.body.length > 2
        result = JSON.parse(resp.body)
        event.set(@target, result)
        filter_matched(event)
      end
    
    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Passivetotal")

    end

  end # def filter
end # class LogStash::Filters::Passivetotal
