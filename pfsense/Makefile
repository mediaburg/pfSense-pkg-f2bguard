PORTNAME=       f2bguard
PORTVERSION=    0.1.7
CATEGORIES=     security
PKGNAMEPREFIX=  pfSense-pkg-
MASTER_SITES=   # empty
DISTFILES=      # empty
EXTRACT_ONLY=    # empty

MAINTAINER=     mediaburg@users.noreply.github.com
COMMENT=        pfSense integration for Fail2Ban Guard

LICENSE=        BSD2CLAUSE

NO_BUILD=       yes
NO_ARCH=        yes
NO_MTREE=       yes
USES=           python:3.11+
RUN_DEPENDS=    ${PYTHON_PKGNAMEPREFIX}sqlite3>0:databases/py-sqlite3@${PY_FLAVOR}

SUB_FILES=      pkg-install pkg-deinstall
# /etc/rc.packages accepts either form after stripping the pfSense-pkg-
# prefix. Use the native full package name, matching established packages.
SUB_LIST=       PORTNAME=pfSense-pkg-${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/rc.d
	${MKDIR} ${STAGEDIR}${PREFIX}/www
	${MKDIR} ${STAGEDIR}${PREFIX}/share/pfSense-pkg-f2bguard
	${MKDIR} ${STAGEDIR}${DATADIR}/f2bguard
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/f2bguard.xml ${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/f2bguard.inc ${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/pfSense-pkg-f2bguard/info.xml ${STAGEDIR}${PREFIX}/share/pfSense-pkg-f2bguard
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/etc/rc.d/f2bguard ${STAGEDIR}${PREFIX}/etc/rc.d
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/f2bguard.php ${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/f2bguard_clients.php ${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/f2bguard_jails.php ${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/f2bguard_status.php ${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/f2bguard.priv.inc ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/f2bguard/*.py ${STAGEDIR}${DATADIR}/f2bguard
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|g" \
		${STAGEDIR}${PREFIX}/share/pfSense-pkg-f2bguard/info.xml
	@${REINPLACE_CMD} -i '' -e "s|%%PYTHON_CMD%%|${PYTHON_CMD}|g" \
		${STAGEDIR}${PREFIX}/etc/rc.d/f2bguard \
		${STAGEDIR}${PREFIX}/pkg/f2bguard.xml

.include <bsd.port.mk>
