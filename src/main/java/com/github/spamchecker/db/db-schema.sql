-- PUBLIC.PROVIDER definition

-- Drop table

-- DROP TABLE PROVIDER;

CREATE TABLE PROVIDER (
	ID BIGINT NOT NULL AUTO_INCREMENT,
	URL CHARACTER VARYING(255) NOT NULL,
	CONSTRAINT PROVIDER_PK PRIMARY KEY (ID)
);

-- PUBLIC."DOMAIN" definition

-- Drop table

-- DROP TABLE "DOMAIN";

CREATE TABLE "DOMAIN" (
	ID BIGINT NOT NULL AUTO_INCREMENT,
	NAME CHARACTER VARYING(255) NOT NULL,
	PROVIDER BIGINT,
	CLASSIFICATION CHARACTER VARYING(32) NOT NULL,
	HEURISTICS CHARACTER VARYING(32) NOT NULL,

	CONSTRAINT DOMAIN_PK PRIMARY KEY (ID)
);
ALTER TABLE PUBLIC."DOMAIN" ADD CONSTRAINT DOMAIN_FK FOREIGN KEY (PROVIDER) REFERENCES PUBLIC.PROVIDER(ID) ON DELETE CASCADE ON UPDATE RESTRICT;


-- PUBLIC.MX definition

-- Drop table

-- DROP TABLE MX;

CREATE TABLE MX (
	ID BIGINT NOT NULL AUTO_INCREMENT,
	NAME BINARY VARYING(255) NOT NULL,

	CLASSIFICATION CHARACTER VARYING(32) NOT NULL,
	HEURISTICS CHARACTER VARYING(32) NOT NULL,

	CONSTRAINT MX_PK PRIMARY KEY (ID)
);

CREATE TABLE MX_USAGE (
	DOMAIN BIGINT NOT NULL AUTO_INCREMENT,
	MX BIGINT NOT NULL AUTO_INCREMENT,
	CONSTRAINT MX_USAGE_PK PRIMARY KEY (DOMAIN, MX)
);

-- PUBLIC.MX foreign keys

ALTER TABLE PUBLIC.MX_USAGE ADD CONSTRAINT MX_USAGE_FK1 FOREIGN KEY ("DOMAIN") REFERENCES "DOMAIN"(ID) ON DELETE CASCADE ON UPDATE RESTRICT;
ALTER TABLE PUBLIC.MX_USAGE ADD CONSTRAINT MX_USAGE_FK2 FOREIGN KEY ("MX") REFERENCES "MX"(ID) ON DELETE CASCADE ON UPDATE RESTRICT;


-- PUBLIC.IP definition

-- Drop table

-- DROP TABLE IP;

CREATE TABLE IP (
	ID BIGINT NOT NULL AUTO_INCREMENT,
	ADDRESS CHARACTER VARYING NOT NULL,
	
	CLASSIFICATION CHARACTER VARYING(32) NOT NULL,
	HEURISTICS CHARACTER VARYING(32) NOT NULL,

	CONSTRAINT IP_PK PRIMARY KEY (ID)
);

CREATE TABLE IP_USAGE (
	MX BIGINT NOT NULL,
	IP BIGINT NOT NULL,
	
	CONSTRAINT IP_USAGE_PK PRIMARY KEY (MX, IP)
);

ALTER TABLE PUBLIC.IP_USAGE ADD CONSTRAINT IP_USAGE_FK1 FOREIGN KEY ("MX") REFERENCES "MX"(ID) ON DELETE CASCADE ON UPDATE RESTRICT;
ALTER TABLE PUBLIC.IP_USAGE ADD CONSTRAINT IP_USAGE_FK2 FOREIGN KEY ("IP") REFERENCES "IP"(ID) ON DELETE CASCADE ON UPDATE RESTRICT;

