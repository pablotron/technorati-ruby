#!/usr/bin/env ruby

#######################################################################
# referrer_rss.rb - build a RSS feed of site referrers                #
# by Paul Duncan <pabs@pablotron.org>                                 #
#######################################################################

# load technorati bindings
require 'cgi'
require 'time'
require 'erb'
require 'technorati'

class Technorati
  class Referrer
    def self.run(args)
      url = args.shift || 'pablotron.org'
      key = Technorati.load_key
      puts Referrer.new(key).run(url)
    end

    def initialize(key)
      @tr = Technorati.new(key)
      @tmpl = {
        :rss  => ERB.new(RSS_TMPL),
        :item => ERB.new(ITEM_TMPL),
      }
    end

    def run(url)
      results = @tr.cosmos(url)
      @tmpl[:rss].result(binding)
    end

    private

    def h(str)
      CGI.escapeHTML(str)
    end

    def u(str)
      CGI.escape(str)
    end

    def rss_item(url, item)
      @tmpl[:item].result(binding)
    end

    RSS_TMPL = <<-END_RSS_TMPL
<?xml version='1.0' encoding='utf-8'?>
<rss version='2.0'>
  <channel>
    <title>Technorati: Sites Linking to <%= h(url) %></title>
    <link>http://technorati.com/</link>
    <description>
      A list of sites linking to <%= h(url) %> according to 
      &lt;a href='http://technorati.com/'&gt;Technorati&lt;/a&gt;.
    </description>

    <%= results['items'].map { |item| rss_item(url, item) }.join %>
  </channel>
</rss>
END_RSS_TMPL

    ITEM_TMPL = <<-END_ITEM_TMPL
  <item>
    <title><%= h(item['weblog/name']) %></title>
    <link><%= h(item['weblog/url'])</link>
    <pubDate><%= h(item['linkcreated'].httpdate) %></pubDate>
    <description>
      This site links to <%= h(url) %>. 
      <%= h(item['exerpt'] ? 'Exerpt:' << item['exerpt'] : '') %>
    </description>
  </item>"
END_ITEM_TMPL
  end
end

Technorati::Referrer.run(ARGV) if __FILE__ == $0
