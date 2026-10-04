from conan import ConanFile
class C(ConanFile):
    requires = "mbedtls/3.5.0"
    def requirements(self):
        self.requires("fmt/10.0")
        self.requires("wolfssl/5.6.0")
