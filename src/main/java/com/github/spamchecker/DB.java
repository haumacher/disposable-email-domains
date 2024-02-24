package com.github.spamchecker;
import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

public interface DB {

	@Select("select DISPOSABLE from MAIL_DOMAIN where NAME=#{domain}")
	Boolean lookupDisposable(String domain);

	@Insert("insert into MAIL_DOMAIN (NAME, DISPOSABLE, SERVICE) values (#{domain}, true, #{serviceId})")
	int insertDomain(String domain, Long serviceId);

	@Insert("insert into MX (MAIL_DOMAIN, MX) values (#{domain}, #{mailServer})")
	int insertMx(String domain, String mailServer);

	@Select("select IP from MX_IP where MX=#{mailServer}")
	List<String> getAddresses(String mailServer);

	@Insert("insert into MX_IP (MX, IP) values (#{mailServer}, #{address})")
	int insertMxIp(String mailServer, String address);

	@Select("select ID from MAIL_SERVICE where NAME=#{service}")
	Long getServiceId(String service);

	@Insert("insert into MAIL_SERVICE (NAME) values (#{name})")
    @Options(flushCache = Options.FlushCachePolicy.TRUE, useGeneratedKeys = true, keyProperty = "id", keyColumn="ID")
	Long insertService(Service service);

	@Select("select DEAD from MAIL_HOST where NAME=#{mailServer}")
	Boolean getHostState(String mailServer);

	@Insert("insert into MAIL_HOST (NAME) values (#{mailServer})")
	int insertMailHost(String mailServer);

	@Update("update MAIL_DOMAIN set SERVICE=#{serviceId} where NAME=#{domain} and SERVICE is null")
	int updateDomain(String domain, Long serviceId);

}
