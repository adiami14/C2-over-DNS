;
; BIND data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.adiami.com. amdin.adiami.com. (
			      5		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
; Name servers
adiami.com.    IN      NS      ns1.adiami.com.
adiami.com.    IN      NS      ns2.adiami.com.
; A records for name servers
ns1             IN      A       192.0.2.1
ns2             IN      A       192.0.2.2

; Other A records
@               IN      A       192.0.2.3
www             IN      A       192.0.2.3