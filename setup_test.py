from distutils.core import setup
from distutils.extension import Extension
from Pyrex.Distutils import build_ext
setup(
  name = "test",
  ext_modules=[
    Extension("test", ["test.pyx"], libraries = [])
    ],
  cmdclass = {'build_ext': build_ext}
)

