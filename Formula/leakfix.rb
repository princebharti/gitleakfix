class Leakfix < Formula
  desc "One-stop CLI tool to detect, remove and prevent secrets in git repositories"
  homepage "https://github.com/princebharti/leakfix"
  url "https://github.com/princebharti/leakfix/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "aba2c7c1bb2e9fd616769eed58d1d8a8ef563907a3417a641235ac88099c4bb0"
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
