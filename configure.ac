AC_INIT(Ksplice, 0.8.4, ksplice@mit.edu)

dnl The author of Ksplice learned how to configure libbfd by looking at
dnl elf2flt, which is available under the GNU General Public License.

AC_ARG_WITH(libbfd,
  [ --with-libbfd=<file>  path to libbfd.a ],
  [ ac_libbfd=$withval ],
  [ ac_libbfd=NONE ]
)

AC_ARG_WITH(libiberty,
  [ --with-libiberty=<file>  path to libiberty.a ],
  [ ac_libiberty=$withval ],
  [ ac_libiberty=NONE ]
)

AC_ARG_WITH(bfd-include-dir,
  [ --with-bfd-include-dir=<dir>  path to bfd.h ],
  [ ac_bfd_include_dir=$withval ],
  [ ac_bfd_include_dir=NONE ]
)

AC_PROG_CC
AC_CHECK_HEADERS(bfd.h,, BFD_H="no")

if test "$ac_libiberty" = "NONE"; then
  AC_CHECK_LIB(iberty, objalloc_create)
  ac_libiberty=auto
else
  LIBS="$ac_libiberty $LIBS"
fi
if test "$ac_libbfd" = "NONE"; then
  AC_CHECK_LIB(bfd, bfd_openr)
  ac_libbfd=auto
else
  LIBS="$ac_libbfd $LIBS"
fi

bfd_include_dir=
if test "$ac_bfd_include_dir" != "NONE"; then
  bfd_include_dir="-I$ac_bfd_include_dir"
fi

if ! test -e "objdiff-static" || ! test -e "objmanip-static"; then
  if test "$ac_libbfd" = "NONE" || test "$ac_libiberty" = "NONE"; then
    echo
    echo "Ksplice could not locate libbfd.a and/or libiberty.a on your system."
    echo "You can obtain these libraries from the GNU binutils collection."
    echo "These libraries are available on many Linux distributions as a"
    echo "package called 'binutils-dev' or 'binutils-devel'."
    echo "If your distribution does not provide GNU binutils, you can install"
    echo "GNU binutils from source -- see http://www.gnu.org/software/binutils/."
    echo
    echo "If these libraries are already installed on your system, then you need"
    echo "to tell Ksplice where to find them by running configure again:"
    echo
    echo "  ./configure --with-libbfd=<libbfd.a> --with-libiberty=<libiberty.a>"
    echo
    exit 1
  fi

  if test "$BFD_H" = "no"; then
    echo
    echo "Ksplice could not locate bfd.h on your system."
    echo "If this header file is already installed on your system, then you need"
    echo "to tell Ksplice where to find it by running configure again:"
    echo
    echo "  ./configure --with-bfd-include-dir=<directory-containing-bfd.h>"
    echo
    exit 1
  fi
fi

AC_PROG_SED

AC_PATH_PROG(RSYNC, rsync)
AC_PATH_PROG(PATCH, patch)
AC_PATH_PROG(POD2MAN, pod2man)
if test "$RSYNC" = ""; then
  echo
  echo "Ksplice could not locate rsync on your system."
  echo
  exit 1
fi
if test "$PATCH" = ""; then
  echo
  echo "Ksplice could not locate patch on your system."
  echo
  exit 1
fi
if test "$POD2MAN" = ""; then
  echo
  echo "Ksplice could not locate pod2man on your system."
  echo
  exit 1
fi

AC_PROG_PERL_MODULES(Cwd,,AC_MSG_ERROR(Required perl module Cwd not found))
AC_PROG_PERL_MODULES(Pod::Usage,,AC_MSG_ERROR(Required perl module Pod::Usage not found))
AC_PROG_PERL_MODULES(File::Temp,,AC_MSG_ERROR(Required perl module File::Temp not found))

AC_SUBST(bfd_include_dir)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
