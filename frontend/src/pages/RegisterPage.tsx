import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, User, AlertTriangle, CheckCircle, ArrowRight, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const { register, user } = useAuth();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // If already authenticated, redirect to dashboard
  if (user) {
    navigate('/dashboard', { replace: true });
    return null;
  }

  // Password rules validation
  const rules = [
    { label: 'At least 8 characters', met: password.length >= 8 },
    { label: 'One uppercase letter (A-Z)', met: /[A-Z]/.test(password) },
    { label: 'One lowercase letter (a-z)', met: /[a-z]/.test(password) },
    { label: 'One digit (0-9)', met: /[0-9]/.test(password) },
    { label: 'One special symbol (!@#$%^&*)', met: /[!@#$%^&*(),.?":{}|<>\-_]/.test(password) },
  ];

  const allRulesMet = rules.every((r) => r.met);
  const passwordsMatch = password && confirmPassword && password === confirmPassword;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!fullName.trim()) {
      setError('Full name is required.');
      return;
    }

    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('Please provide a valid email address.');
      return;
    }

    if (!allRulesMet) {
      setError('Password does not meet the minimum security requirements.');
      return;
    }

    if (!passwordsMatch) {
      setError('Passwords do not match. Please re-enter confirmation.');
      return;
    }

    setLoading(true);
    try {
      await register({
        full_name: fullName.trim(),
        email: email.trim().toLowerCase(),
        password,
        confirm_password: confirmPassword
      });
      // Redirect to login with success state
      navigate('/login', {
        state: { message: 'Account created successfully! Please sign in with your credentials.' }
      });
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please check your inputs and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-8rem)] flex items-center justify-center px-4 py-12 cyber-grid">
      <div className="w-full max-w-md space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#111111] border border-[#39FF88]/40 text-[#39FF88] shadow-[0_0_20px_rgba(57,255,136,0.15)] mb-2">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#F5F5F5]">
            Create Your Account
          </h1>
          <p className="text-xs text-[#A3A3A3]">
            Your account keeps your previously checked links private
          </p>
        </div>

        {/* Form Container */}
        <div className="p-6 rounded-xl bg-[#0A0A0A] border border-[#181818] shadow-2xl space-y-5">
          {error && (
            <div className="p-3.5 rounded bg-[#1A0A0A] border border-[#FF525C]/40 flex items-start gap-3 text-xs text-[#FF525C]">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-[#FF525C]" />
              <div className="flex-1 font-medium">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Full Name */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#A3A3A3]">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#737373]" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Jane Doe"
                  className="w-full pl-9 pr-3.5 py-2.5 rounded bg-[#111111] border border-[#292929] text-sm text-[#F5F5F5] placeholder-[#737373] focus:outline-none focus:border-[#39FF88] focus:ring-1 focus:ring-[#39FF88] transition-all"
                />
              </div>
            </div>

            {/* Email Address */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#A3A3A3]">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#737373]" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@example.com"
                  className="w-full pl-9 pr-3.5 py-2.5 rounded bg-[#111111] border border-[#292929] text-sm text-[#F5F5F5] placeholder-[#737373] focus:outline-none focus:border-[#39FF88] focus:ring-1 focus:ring-[#39FF88] transition-all"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#A3A3A3]">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#737373]" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 8 characters"
                  className="w-full pl-9 pr-10 py-2.5 rounded bg-[#111111] border border-[#292929] text-sm text-[#F5F5F5] placeholder-[#737373] focus:outline-none focus:border-[#39FF88] focus:ring-1 focus:ring-[#39FF88] transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#737373] hover:text-[#F5F5F5] transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm Password */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#A3A3A3]">Confirm Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#737373]" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter password"
                  className="w-full pl-9 pr-3.5 py-2.5 rounded bg-[#111111] border border-[#292929] text-sm text-[#F5F5F5] placeholder-[#737373] focus:outline-none focus:border-[#39FF88] focus:ring-1 focus:ring-[#39FF88] transition-all"
                />
              </div>
              {confirmPassword && !passwordsMatch && (
                <p className="text-[11px] text-[#FF525C] mt-1">Passwords do not match.</p>
              )}
            </div>

            {/* Password Policy Tracker */}
            <div className="p-3 rounded bg-[#111111] border border-[#181818] space-y-1.5">
              <span className="text-[10px] uppercase font-semibold text-[#737373] tracking-wider">
                Password Security Requirements
              </span>
              <div className="grid grid-cols-1 gap-1 text-[11px]">
                {rules.map((r, i) => (
                  <div key={i} className="flex items-center gap-1.5">
                    <CheckCircle
                      className={`w-3.5 h-3.5 shrink-0 ${
                        r.met ? 'text-[#39FF88]' : 'text-[#292929]'
                      }`}
                    />
                    <span className={r.met ? 'text-[#F5F5F5]' : 'text-[#737373]'}>
                      {r.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !allRulesMet || !passwordsMatch}
              className="w-full py-2.5 px-4 rounded font-semibold text-sm bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(57,255,136,0.2)]"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-[#050505] border-t-transparent rounded-full animate-spin" />
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="pt-4 border-t border-[#181818] text-center text-xs text-[#737373]">
            Already have an account?{' '}
            <Link to="/login" className="text-[#39FF88] hover:underline font-medium">
              Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
