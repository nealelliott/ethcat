AC_INIT([ethcat], [1.0], [nealelliott@netscape.net])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_CANONICAL_HOST
AC_MSG_CHECKING([for a supported OS])
case "${host_os}" in
     *linux*) 
     	AC_MSG_RESULT([ok (${host_os})])
	AC_DEFINE([LINUX],1,[linux define])
        ;;

           *) 
     	AC_MSG_RESULT([no (${host_os})])
	AC_MSG_ERROR([currently, Linux specific. doesn't support ${host_os} Sorry])
esac
AC_OUTPUT
