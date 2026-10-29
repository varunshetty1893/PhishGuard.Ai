import React from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, CheckCircle2, Database, EyeOff, Info, Search, ShieldAlert, ShieldCheck } from 'lucide-react';

const steps = [
  ['1', 'Paste the link', 'Enter a full website address. The page at that address is not loaded in your browser.', Search],
  ['2', 'Check the address', 'We look for warning signs, such as a look-alike name, an unusual address, or sign-in words used in a suspicious way.', AlertTriangle],
  ['3', 'Check known threats', 'The address is checked against local OpenPhish and Phishing.Database feeds, PhishDestroy and PhishStats, and Google Safe Browsing when configured.', Database],
  ['4', 'Show a result', 'You see the risk score, a plain-language verdict, warning signs, and suggested next steps.', CheckCircle2],
] as const;

export const AboutPage: React.FC = () => (
  <div className="pb-16">
    <section className="border-b border-[#181818] px-4 py-14 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-3xl space-y-5 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-[#39FF88]/40 bg-[#0E1A12] px-3 py-1 text-xs font-semibold text-[#39FF88]"><EyeOff className="h-3.5 w-3.5" />The submitted link is not opened</span>
        <h1 className="text-3xl font-extrabold tracking-tight text-[#F5F5F5] sm:text-5xl">How PhishGuard AI <span className="text-[#39FF88]">Works</span></h1>
        <p className="mx-auto max-w-2xl text-base leading-relaxed text-[#A3A3A3]">Paste a link you are unsure about. We inspect the address itself, look for warning signs, and—when available—check known-threat services. We do not open the submitted website.</p>
      </div>
    </section>

    <section className="mx-auto max-w-5xl space-y-7 px-4 py-14 sm:px-6 lg:px-8">
      <div className="space-y-2"><p className="text-xs font-semibold uppercase tracking-wider text-[#39FF88]">The check, step by step</p><h2 className="text-2xl font-bold text-[#F5F5F5]">What happens when you check a link</h2></div>
      <div className="grid gap-4 md:grid-cols-4">
        {steps.map(([number, title, text, Icon]) => <article key={number} className="relative space-y-3 rounded border border-[#292929] bg-[#111111] p-5"><span className="absolute right-4 top-4 font-mono text-xs font-bold text-[#39FF88]">0{number}</span><div className="inline-flex rounded border border-[#39FF88]/30 bg-[#0E1A12] p-2 text-[#39FF88]"><Icon className="h-5 w-5" /></div><h3 className="text-sm font-semibold text-[#F5F5F5]">{title}</h3><p className="text-xs leading-relaxed text-[#A3A3A3]">{text}</p></article>)}
      </div>
    </section>

    <section className="border-y border-[#181818] bg-[#0A0A0A] px-4 py-14 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-5xl space-y-7">
        <div className="space-y-2"><p className="text-xs font-semibold uppercase tracking-wider text-[#FFD54A]">Understanding the result</p><h2 className="text-2xl font-bold text-[#F5F5F5]">What the verdict means</h2><p className="max-w-3xl text-sm leading-relaxed text-[#A3A3A3]">A result is advice based on the address and any known-threat matches. It is not a promise that a website is safe or dangerous.</p></div>
        <div className="grid gap-4 md:grid-cols-3">
          <div className="space-y-3 rounded border border-[#39FF88]/30 bg-[#0E1A12] p-5"><ShieldCheck className="h-6 w-6 text-[#39FF88]" /><h3 className="font-semibold text-[#F5F5F5]">Likely Safe</h3><p className="text-xs leading-relaxed text-[#A3A3A3]">No major warning signs were found. Stay careful if the page unexpectedly asks for a password, money, or personal information.</p></div>
          <div className="space-y-3 rounded border border-[#FFD54A]/30 bg-[#1A170A] p-5"><AlertTriangle className="h-6 w-6 text-[#FFD54A]" /><h3 className="font-semibold text-[#F5F5F5]">Suspicious</h3><p className="text-xs leading-relaxed text-[#A3A3A3]">Some warning signs were found. Do not sign in or pay until you verify the address independently.</p></div>
          <div className="space-y-3 rounded border border-[#FF525C]/30 bg-[#1A0D0F] p-5"><ShieldAlert className="h-6 w-6 text-[#FF525C]" /><h3 className="font-semibold text-[#F5F5F5]">Likely Phishing</h3><p className="text-xs leading-relaxed text-[#A3A3A3]">Strong warning signs or a known-threat match were found. Do not enter passwords, payment details, or download files.</p></div>
        </div>
      </div>
    </section>

    <section className="mx-auto max-w-5xl space-y-7 px-4 py-14 sm:px-6 lg:px-8">
      <div className="space-y-2"><p className="text-xs font-semibold uppercase tracking-wider text-[#39FF88]">About the current detection system</p><h2 className="text-2xl font-bold text-[#F5F5F5]">It learns patterns, but it is not perfect</h2><p className="max-w-3xl text-sm leading-relaxed text-[#A3A3A3]">The current model was trained on 40,000 examples. It uses the shape and words of an address—not the contents of the website—to estimate how suspicious it looks.</p></div>
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded border border-[#292929] bg-[#111111] p-5"><div className="text-2xl font-bold text-[#39FF88]">23,913</div><p className="mt-1 text-xs font-semibold text-[#F5F5F5]">Training links</p><p className="mt-1 text-[11px] leading-relaxed text-[#737373]">Examples used to teach the current model.</p></div>
        <div className="rounded border border-[#292929] bg-[#111111] p-5"><div className="text-2xl font-bold text-[#FFD54A]">8,969</div><p className="mt-1 text-xs font-semibold text-[#F5F5F5]">Validation links</p><p className="mt-1 text-[11px] leading-relaxed text-[#737373]">Examples used to select the result cutoff.</p></div>
        <div className="rounded border border-[#292929] bg-[#111111] p-5"><div className="text-2xl font-bold text-[#39FF88]">7,118</div><p className="mt-1 text-xs font-semibold text-[#F5F5F5]">Held-out test links</p><p className="mt-1 text-[11px] leading-relaxed text-[#737373]">Separate links used to measure the model after training.</p></div>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded border border-[#FFD54A]/30 bg-[#1A170A] p-5"><div className="flex items-center gap-2 text-sm font-semibold text-[#FFD54A]"><Info className="h-4 w-4" />Why a real sign-in page may be flagged</div><p className="mt-2 text-xs leading-relaxed text-[#A3A3A3]">Real login, account, billing, and portal pages can look similar to phishing links because they use the same words. In the current 30-link real login/account test, 14 were flagged incorrectly. Treat “Suspicious” as a prompt to verify, not proof that a real service is fake.</p></div>
        <div className="rounded border border-[#FF525C]/30 bg-[#1A0D0F] p-5"><div className="flex items-center gap-2 text-sm font-semibold text-[#FF525C]"><Info className="h-4 w-4" />Why phishing may be missed</div><p className="mt-2 text-xs leading-relaxed text-[#A3A3A3]">New or carefully made phishing links can look normal. A “Likely Safe” result does not prove a page is safe. Use bookmarks, a trusted search result, or the organization’s official app when signing in.</p></div>
      </div>
      <div className="rounded border border-[#292929] bg-[#111111] p-5 text-xs leading-relaxed text-[#A3A3A3]"><strong className="text-[#F5F5F5]">About the score:</strong> The Phishing Risk Score shows how many warning signs the model found. It is not the exact chance that a website is dangerous. A confirmed match from a known-threat service is shown separately because it is different from a model prediction.</div>
    </section>

    <section className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8"><div className="rounded border border-[#39FF88]/30 bg-[#0E1A12] p-8 text-center"><h2 className="text-2xl font-bold text-[#F5F5F5]">Ready to check a link?</h2><p className="mx-auto mt-2 max-w-xl text-sm text-[#A3A3A3]">Paste a full web address. Do not open a suspicious link just to check where it goes.</p><Link to="/scanner" className="mt-5 inline-flex items-center gap-2 rounded bg-[#39FF88] px-5 py-3 text-sm font-bold text-[#050505] transition-colors hover:bg-[#16C96A]">Check a link <ArrowRight className="h-4 w-4" /></Link></div></section>
  </div>
);
