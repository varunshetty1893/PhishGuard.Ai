import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, Mail, AlertTriangle, ArrowRight, Eye, EyeOff, CheckCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, user } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Success message passed from registration
  const successMessage = (location.state as any)?.message;

  // If already authenticated, redirect to dashboard
  if (user) {
    navigate('/dashboard', { replace: true });
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!email.trim()) {
      setError('Email address is required.');
      return;
    }

    if (!password) {
      setError('Password is required.');
      return;
    }

    setLoading(true);
    try {
      await login({
        email: email.trim().toLowerCase(),
        password,
        remember_me: rememberMe
      });
      const destination = (location.state as any)?.from?.pathname || '/dashboard';
      navigate(destination, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Sign-in check failed. Please check your email and password.');
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
            Sign In to PhishGuard AI
          </h1>
          <p className="text-xs text-[#A3A3A3]">
            Access your private URL analysis dashboard and security history
          </p>
        </div>

        {/* Form Container */}
        <div className="p-6 rounded-xl bg-[#0A0A0A] border border-[#181818] shadow-2xl space-y-5">
          {successMessage && (
            <div className="p-3.5 rounded bg-[#0E1A12] border border-[#39FF88]/40 flex items-start gap-3 text-xs text-[#39FF88]">
              <CheckCircle className="w-4 h-4 shrink-0 mt-0.5 text-[#39FF88]" />
              <div className="flex-1 font-medium">{successMessage}</div>
            </div>
          )}

          {error && (
            <div className="p-3.5 rounded bg-[#1A0A0A] border border-[#FF525C]/40 flex items-start gap-3 text-xs text-[#FF525C]">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-[#FF525C]" />
              <div className="flex-1 font-medium">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
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
              <div className="flex items-center justify-between">
                <label className="block text-xs font-medium text-[#A3A3A3]">Password</label>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#737373]" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your account password"
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

            {/* Remember Me */}
            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-2 cursor-pointer text-[#A3A3A3] select-none">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-4 h-4 rounded bg-[#111111] border-[#292929] text-[#39FF88] focus:ring-[#39FF88] focus:ring-offset-0 focus:ring-1 accent-[#39FF88]"
                />
                <span>Remember me for 14 days</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 rounded font-semibold text-sm bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(57,255,136,0.2)]"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-[#050505] border-t-transparent rounded-full animate-spin" />
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="pt-4 border-t border-[#181818] text-center text-xs text-[#737373]">
            Don't have an account yet?{' '}
            <Link to="/register" className="text-[#39FF88] hover:underline font-medium">
              Create an Account
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
