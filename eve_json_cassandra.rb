#!/usr/bin/env ruby

require 'json'
require 'pry'
require 'java'

class EveCassandra
	def load_eve_json
	puts "Loading Parsing Module for Events...."
	f = File.open('/var/log/suricata/eve.json',"r")
   # Since this file exists and is growing, seek to the end of the most recent entry
   f.seek(0,IO::SEEK_END)
   while true
      select([f])
      line=f.read
      parse_event(line) if line!=""
      sleep 1
    end
	end
	def load_eve_to_db(hash)
		# Validate if the event_type=stats , then ignore that event 
		# We will collect the stats details from stats file
		# if stats disabled in suricata.yml , the there would be no stats 
		# But for safe side we should have this condition , else it will fail the Db update 
		

		if hash['event_type'] != 'stats'
			temp_file=File.new('/home/khirod/temp_db.txt','a+')
			key_file = File.new('/home/khirod/key_field.txt','a+')
			hash.each do |k,v|
				temp_file.write(k+' =>  '+v.to_s+"\n")
				key_file.write(k+" : ") unless discovered_parent_fields_array.include?(k)
				if ['tls','dns','flow','tcp','http','fileinfo'].include?(k)
					v.each do |k1,v1|
					unless discover_child_fields_array(k).include?(k1)
						key_file.write(k+'=> '+k1+"  , ")
					end
					end
				end
			end
			temp_file.write("\n========================================+++++++++++++++++++++++++++++++++++++++++++++++++++========================================\n")
			temp_file.close
			key_file.close
		end
	end
	def discovered_parent_fields_array
		dfa=["timestamp","flow_id","in_iface","event_type","src_ip","src_port","dest_ip","dest_port","proto","tls","dns","flow",
		     "tcp","app_proto","tx_id","http","alert","payload","payload_printable","stream","packet","fileinfo","icmp_type", "icmp_code"] 
	         
	    dfa     
	end
	def discover_child_fields_array(key)
		tls=["subject", "issuerdn", "fingerprint", "sni", "version"]
		dns=["type","id","rrname", "rrtype", "tx_id","rcode","ttl","rdata"]
		flow=["pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "start", "end", "age", "state", "reason"]
		tcp=["tcp_flags", "tcp_flags_ts", "tcp_flags_tc", "syn", "rst", "psh", "ack", "state","fin"]
		http=["hostname", "url", "http_user_agent", "http_refer", "http_method", "protocol", "length","http_content_type","status","redirect"]
		fileinfo=["filename", "state", "stored", "size", "tx_id"]
		case key
		when 'tls'
			return tls
		when 'dns'
			return dns
		when 'flow'
			return flow
		when 'tcp'
			return tcp
		when 'http'
			return http
		when 'fileinfo'
			return fileinfo
		end

	end
	def parse_event(line)
		pat="{\"timestamp\""
		if line.split(pat).size>2
			event_array=line.split(pat)[1..-1]
			event_array.each do|e|
			  event=pat+e
			  load_eve_to_db((JSON.parse event.gsub('=>', ':')))
			  #puts "========================================\n"
			end
		else
			event=pat+line.split(pat)[1..-1].shift
			load_eve_to_db((JSON.parse event.gsub('=>', ':')))
			#puts "========================================\n"
		end
	end
end

EveCassandra.new.load_eve_json
