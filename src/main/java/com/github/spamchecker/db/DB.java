package com.github.spamchecker.db;
import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import com.github.spamchecker.db.model.Domain;
import com.github.spamchecker.db.model.Ip;
import com.github.spamchecker.db.model.Mx;

public interface DB {

	@Select("select CLASSIFICATION from DOMAIN where NAME=#{domain}")
	Boolean lookupDisposable(String domain);

	@Insert("insert into DOMAIN (NAME, PROVIDER, CLASSIFICATION, HEURISTICS) values (#{name}, #{provider}, #{classification}, #{heuristics})")
    @Options(flushCache = Options.FlushCachePolicy.TRUE, useGeneratedKeys = true, keyProperty = "id", keyColumn="ID")
	int insertDomain(Domain domain);
	
	@Insert("insert into MX (NAME, CLASSIFICATION, HEURISTICS) values (#{name}, #{classification}, #{heuristics})")
	@Options(flushCache = Options.FlushCachePolicy.TRUE, useGeneratedKeys = true, keyProperty = "id", keyColumn="ID")
	int insertMx(Mx mx);
	
	@Select("select ID from MX where NAME=#{name}")
	long getMxId(String name);

	@Select("select ADDRESS from IP where MX=#{mx}")
	List<String> getAddresses(long mx);

	@Insert("insert into IP (ADDRESS, CLASSIFICATION, HEURISTICS) values (#{address}, #{classification}, #{heuristics})")
	int insertIp(Ip ip);

	@Insert("insert into IP_USAGE (MX, IP) values (#{mx}, #{ip},)")
	int insertIpUsage(long mx, long ip);
	
	@Insert("insert into MX_USAGE (DOMAIN, MX) values (#{domain}, #{mx},)")
	int insertMxUsage(long domain, long mx);
	
	@Select("select ID from PROVIDER where URL=#{url}")
	Long getServiceId(String url);

	@Insert("insert into PROVIDER (URL) values (#{url})")
	int insertService(String url);

	@Select("select CLASSIFICATION from MAIL_HOST where NAME=#{mailServer}")
	Boolean getHostState(String mailServer);

	@Insert("insert into MAIL_HOST (NAME) values (#{mailServer})")
	int insertMailHost(String mailServer);

	@Update("update MAIL_DOMAIN set SERVICE=#{serviceId} where NAME=#{domain} and SERVICE is null")
	int updateDomain(String domain, Long serviceId);

}
