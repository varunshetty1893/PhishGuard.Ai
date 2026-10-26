import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Eye, Database, AlertTriangle,
  ArrowRight, BookOpen,
  Info
} from 'lucide-react';
import { MLLabPage } from './MLLabPage';

export const AboutPage: React.FC = () => {
  return (
    <div className="space-y-0 pb-16">

      {/* Hero Banner */}
      <section className="relative pt-12 pb-12 px-4 sm:px-6 lg:px-8 border-b border-[#181818] cyber-grid">
        <div className="max-w-4xl mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#111111] border border-[#FFD54A]/40 text-xs font-medium text-[#FFD54A]">
            <BookOpen className="w-3 h-3" />
            <span>Plain-English Guide — No Technical Background Needed</span>
          </div>
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-[#F5F5F5]">
            How Does <span className="text-[#39FF88]">PhishGuard AI</span> Work?
          </h1>
          <p className="text-base sm:text-lg text-[#A3A3A3] max-w-2xl mx-auto leading-relaxed">
            A simple, step-by-step explanation of what PhishGuard AI does, how it was built,
            and why it's safe to use — written for everyone, not just programmers.
          </p>
        </div>
      </section>

      {/* What is Phishing */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-14 space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded bg-[#1A0A0A] border border-[#FF525C]/40 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-[#FF525C]" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-[#F5F5F5]">What is Phishing?</h2>
            <p className="text-xs text-[#A3A3A3]">The problem this application solves</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-3">
            <h3 className="font-semibold text-[#FF525C] text-sm">🎣 What Attackers Do</h3>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              Cybercriminals create <strong className="text-[#F5F5F5]">fake websites</strong> that look
              exactly like real ones — your bank, PayPal, Gmail, or Amazon. They send you a link
              to this fake site and trick you into entering your password or credit card number.
            </p>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              The link looks almost real. For example: <code className="text-[#FF525C] bg-[#0A0A0A] px-1 rounded">
                paypal.com.verify-login.xyz
              </code> — notice it says "paypal.com" but the real domain is "xyz".
            </p>
          </div>

          <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-3">
            <h3 className="font-semibold text-[#39FF88] text-sm">🛡️ What PhishGuard AI Does</h3>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              Before you click any suspicious link, you can <strong className="text-[#F5F5F5]">paste it here</strong>.
              PhishGuard AI checks the address — without visiting the website —
              and tells you whether it shows warning signs.
            </p>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              Think of it like a <strong className="text-[#F5F5F5]">security guard who examines
              a visitor's ID</strong> before letting them through the door.
            </p>
          </div>
        </div>
      </section>

      {/* How It Works - Step by Step */}
      <section className="bg-[#0A0A0A] border-y border-[#181818]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-14 space-y-8">
          <div className="text-center space-y-2">
            <h2 className="text-2xl font-bold text-[#F5F5F5]">What Happens When You Scan a Link?</h2>
            <p className="text-sm text-[#A3A3A3]">Four automatic steps happen in under 2 seconds</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                step: '01',
                title: 'You Paste the Link',
                desc: 'You copy-paste the suspicious URL into the Scanner. The website address is never clicked or opened by your browser.',
                icon: '📋',
                color: '#39FF88'
              },
              {
                step: '02',
                title: 'We Check the Address',
                desc: 'We look for 16 common warning signs, such as extra dots, an unencrypted connection, or a number-based address instead of a website name.',
                icon: '🔍',
                color: '#39FF88'
              },
              {
                step: '03',
                title: 'We Compare Warning Signs',
                desc: 'Our detection system compares these signs with examples of phishing and safe links.',
                icon: '🤖',
                color: '#FFD54A'
              },
              {
                step: '04',
                title: 'You Get a Safety Report',
                desc: 'Within seconds, you receive a clear result: Likely Safe ✅, Suspicious ⚠️, or Likely Phishing 🔴, with an explanation of why.',
                icon: '📊',
                color: '#FFD54A'
              },
            ].map((item) => (
              <div key={item.step} className="p-5 rounded bg-[#111111] border border-[#292929] space-y-3 relative">
                <div className="text-3xl">{item.icon}</div>
                <div
                  className="text-xs font-bold font-mono"
                  style={{ color: item.color }}
                >
                  STEP {item.step}
                </div>
                <h3 className="font-semibold text-[#F5F5F5] text-sm">{item.title}</h3>
                <p className="text-xs text-[#A3A3A3] leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Training examples section */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-14 space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded bg-[#0E1A12] border border-[#39FF88]/40 flex items-center justify-center">
            <Database className="w-5 h-5 text-[#39FF88]" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-[#F5F5F5]">📂 Examples Used to Train the System</h2>
            <p className="text-xs text-[#A3A3A3]">A clear look at the examples used for training</p>
          </div>
        </div>

        {/* Dataset Stats Card */}
        <div className="p-6 rounded bg-[#0E1A12] border border-[#39FF88]/30 space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Total training examples', value: '298,006', sub: 'Links used to test the system' },
              { label: 'Phishing URLs', value: '162,711', sub: 'Verified malicious links' },
              { label: 'Safe (Legitimate) URLs', value: '135,295', sub: 'Verified high-reputation domains' },
              { label: 'Accuracy on test examples', value: '99.40%', sub: '59,602 unseen test links' },
            ].map((stat) => (
              <div key={stat.label} className="p-4 rounded bg-[#111111] border border-[#292929] text-center space-y-1">
                <div className="text-2xl font-bold font-mono text-[#39FF88]">{stat.value}</div>
                <div className="text-xs font-semibold text-[#F5F5F5]">{stat.label}</div>
                <div className="text-[10px] text-[#737373]">{stat.sub}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Phishing Benchmark */}
          <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
            <div className="flex items-start gap-3">
              <span className="text-2xl">🎣</span>
              <div>
                <h3 className="font-bold text-[#FF525C] text-sm">Known Phishing Examples</h3>
                <p className="text-[10px] text-[#737373] mt-0.5">Reported dangerous links</p>
              </div>
            </div>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              These are reported phishing links, including fake sign-in pages, fake payment pages, and look-alike brand links.
            </p>
          </div>

          {/* Legitimate Domain Baseline */}
          <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
            <div className="flex items-start gap-3">
              <span className="text-2xl">✅</span>
              <div>
                <h3 className="font-bold text-[#39FF88] text-sm">Known Safe Examples</h3>
                <p className="text-[10px] text-[#737373] mt-0.5">Examples from established websites</p>
              </div>
            </div>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              These include many established websites from businesses, banks, news organizations, and schools.
            </p>
          </div>
        </div>

        {/* What features the AI looks at */}
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <h3 className="font-semibold text-[#F5F5F5] text-sm flex items-center gap-2">
            <Eye className="w-4 h-4 text-[#FFD54A]" />
            What Patterns Does the AI Look For in a URL?
          </h3>
          <p className="text-xs text-[#A3A3A3]">
            The AI was taught to notice <strong className="text-[#F5F5F5]">16 suspicious patterns</strong> in a URL.
            Here are the most important ones explained in plain English:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { signal: '🔢 Too many numbers', detail: 'Phishing links often hide behind IP addresses like 192.168.1.1 instead of real domain names.' },
              { signal: '🔒 Missing HTTPS', detail: 'Safe websites use "https://" (the padlock). Phishing sites often use "http://" without encryption.' },
              { signal: '🟡 Too many dots', detail: 'Fake sites stack subdomains: e.g. paypal.com.login.verify.xyz — the real site is "xyz", not PayPal.' },
              { signal: '📏 Very long URL', detail: 'Phishing URLs are often unusually long to confuse victims and hide the real destination.' },
              { signal: '🌐 Raw IP address', detail: 'Legitimate sites always use domain names. A URL like http://198.51.100.4/login is almost always suspicious.' },
              { signal: '🔗 URL shorteners', detail: 'Services like bit.ly hide where a link actually goes. The AI flags these for extra caution.' },
              { signal: '⚠️ Suspicious words', detail: 'Words like "login", "verify", "secure", "update" in unusual combinations are a red flag.' },
              { signal: '📌 @ symbol', detail: 'The @ symbol can be abused to trick browsers into ignoring the real domain name.' },
              { signal: '🔌 Unusual port numbers', detail: 'Real sites use standard ports. A URL with :8080 or :1337 is unusual for a legitimate service.' },
            ].map((item) => (
              <div key={item.signal} className="p-3 rounded bg-[#0A0A0A] border border-[#181818] space-y-1">
                <div className="text-xs font-semibold text-[#F5F5F5]">{item.signal}</div>
                <div className="text-[11px] text-[#A3A3A3] leading-relaxed">{item.detail}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Is it Safe to Use */}
      <section className="bg-[#0A0A0A] border-y border-[#181818]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-14 space-y-6">
          <div className="text-center space-y-2 mb-8">
            <h2 className="text-2xl font-bold text-[#F5F5F5]">🔒 Is It Safe to Paste Links Here?</h2>
            <p className="text-sm text-[#A3A3A3]">Your security and privacy concerns, answered</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                icon: '🚫',
                title: 'We Never Visit the Link',
                desc: 'PhishGuard AI does NOT click or open the link you paste. It only reads the text of the URL — just like reading the label on a package without opening it.',
                color: '#39FF88'
              },
              {
                icon: '📵',
                title: 'No Data Sent to Third Parties',
                desc: 'Your URL is analysed on our local server. The only external checks are optional — Google Safe Browsing and URLhaus threat databases, both run server-side.',
                color: '#39FF88'
              },
              {
                icon: '🔐',
                title: 'Your Device is Protected',
                desc: 'Because we never execute or render the link, no malware, tracking pixels, or browser exploits can reach your device through PhishGuard.',
                color: '#39FF88'
              },
            ].map((item) => (
              <div key={item.title} className="p-6 rounded bg-[#111111] border border-[#292929] space-y-3 text-center">
                <div className="text-4xl">{item.icon}</div>
                <h3 className="font-bold text-[#F5F5F5] text-sm">{item.title}</h3>
                <p className="text-xs text-[#A3A3A3] leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Navigation to Scan */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
        <div className="p-8 rounded bg-[#111111] border border-[#39FF88]/30 text-center space-y-4">
          <div className="inline-flex p-3 rounded-full bg-[#0E1A12] border border-[#39FF88]/40">
            <Shield className="w-8 h-8 text-[#39FF88]" />
          </div>
          <h2 className="text-2xl font-bold text-[#F5F5F5]">Ready to Check a Suspicious Link?</h2>
          <p className="text-sm text-[#A3A3A3] max-w-xl mx-auto">
            Go to the Scanner, paste any link you're not sure about, and get a clear result in seconds.
            The link is not opened during the check.
          </p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center pt-2">
            <Link
              to="/scanner"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] font-bold text-sm tracking-wider uppercase transition-all shadow-[0_0_20px_rgba(57,255,136,0.2)]"
            >
              <span>Go to Scanner</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              to="#detection-details"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded bg-transparent border border-[#292929] text-[#A3A3A3] hover:text-[#F5F5F5] hover:border-[#39FF88]/50 font-medium text-sm transition-all"
            >
              <span>See How the Detection System Is Tested</span>
            </Link>
          </div>
        </div>

        {/* Safety note */}
        <div className="mt-6 p-4 rounded bg-[#111118] border border-[#181818] flex gap-3">
          <Info className="w-4 h-4 text-[#39FF88] shrink-0 mt-0.5" />
          <p className="text-xs text-[#A3A3A3] leading-relaxed">
            <strong className="text-[#39FF88]">How we protect you:</strong> PhishGuard AI checks the text of the address without opening or connecting to the submitted website.
          </p>
        </div>
      </section>

      {/* Detection details are part of How It Works, not a separate page. */}
      <section id="detection-details" className="border-t border-[#181818]">
        <MLLabPage />
      </section>
    </div>
  );
};


