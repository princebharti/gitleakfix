class Leakfix < Formula
  desc "One-stop CLI tool to detect, remove and prevent secrets in git repositories"
  homepage "https://github.com/princebharti/leakfix"
  url "https://github.com/princebharti/leakfix/archive/refs/tags/v1.1.0.tar.gz"
  sha256 "1fd8cbd5fbd32ca905b83ca04e6393fb3da1fd1cace213ce50f6a2c0605f380c"
  license "MIT"

  depends_on "python@3.11"
  depends_on "gitleaks"
  depends_on "git-filter-repo"

  def install
    system "pip3.11", "install", "--prefix=#{prefix}", "--no-deps", "."
    bin.install "bin/leakfix" if File.exist?("bin/leakfix")
  end

  def caveats
    <<~EOS
      ✅ leakfix installed!

      Complete setup (includes optional LLM enhancement):
        leakfix setup

      Or jump straight in:
        leakfix scan        # scan current repo for secrets
        leakfix --help      # all commands

      Note: leakfix setup installs optional AI-powered false
      positive detection that runs 100% locally on your Mac.
    EOS
  end

  test do
    system "#{bin}/leakfix", "--version"
    system "#{bin}/leakfix", "--help"
  end
end
