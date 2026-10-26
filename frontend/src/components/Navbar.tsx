import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  History,
  Settings,
  Menu,
  X,
  Terminal,
  BookOpen,
  User as UserIcon,
  LogOut,
  LogIn
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Navbar: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const authenticatedNavItems = [
    { label: 'Check a Link', path: '/scanner', icon: Terminal },
    { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { label: 'History', path: '/history', icon: History },
    { label: 'How It Works', path: '/about', icon: BookOpen },
    { label: 'Settings', path: '/settings', icon: Settings },
  ];

  const publicNavItems = [
    { label: 'How It Works', path: '/about', icon: BookOpen },
  ];

  const navItems = user ? authenticatedNavItems : publicNavItems;

  const isActive = (path: string) => {
    if (path === '/' && location.pathname === '/') return true;
    return location.pathname === path;
  };

  return (
    <header className="sticky top-0 z-50 bg-[#050505]/90 backdrop-blur-md border-b border-[#292929]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded bg-[#111111] border border-[#39FF88]/40 flex items-center justify-center group-hover:border-[#39FF88] transition-colors">
              <Shield className="w-5 h-5 text-[#39FF88]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-[#F5F5F5] group-hover:text-white">
                  PhishGuard<span className="text-[#39FF88]">.AI</span>
                </span>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-1.5 py-0.5 rounded bg-[#181818] text-[#39FF88] border border-[#39FF88]/30">
                  v2.1
                </span>
              </div>
              <p className="text-[10px] text-[#A3A3A3] hidden sm:block">
                Detect the Threat. Protect Your Digital World.
              </p>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 px-3 py-2 rounded text-sm font-medium transition-all ${
                    active
                      ? 'bg-[#181818] text-[#39FF88] border border-[#292929]'
                      : 'text-[#A3A3A3] hover:text-[#F5F5F5] hover:bg-[#111111]'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${active ? 'text-[#39FF88]' : 'text-[#A3A3A3]'}`} />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* User Auth Controls */}
          <div className="hidden md:flex items-center gap-3">
            {user ? (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#111111] border border-[#292929] text-xs">
                  <div className="w-5 h-5 rounded-full bg-[#181818] border border-[#39FF88]/40 flex items-center justify-center text-[#39FF88]">
                    <UserIcon className="w-3 h-3" />
                  </div>
                  <span className="font-medium text-[#F5F5F5] max-w-[120px] truncate" title={user.full_name}>
                    {user.full_name}
                  </span>
                </div>
                <button
                  onClick={handleLogout}
                  className="px-3 py-1.5 rounded border border-[#292929] bg-[#111111] hover:bg-[#1A0A0A] hover:border-[#FF525C]/40 text-[#A3A3A3] hover:text-[#FF525C] text-xs font-medium transition-colors flex items-center gap-1.5"
                  title="Sign out of account"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Logout</span>
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Link
                  to="/login"
                  className="px-3 py-1.5 rounded border border-[#292929] hover:bg-[#111111] text-[#A3A3A3] hover:text-[#F5F5F5] text-xs font-medium transition-colors flex items-center gap-1.5"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-3.5 py-1.5 rounded bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] font-semibold text-xs transition-colors shadow-[0_0_12px_rgba(57,255,136,0.2)]"
                >
                  Register
                </Link>
              </div>
            )}
          </div>

          {/* Mobile Menu Button */}
          <div className="flex md:hidden">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded text-[#A3A3A3] hover:text-[#F5F5F5] hover:bg-[#111111] focus:outline-none"
              aria-label="Toggle Navigation Menu"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-[#0A0A0A] border-b border-[#292929] px-4 pt-2 pb-4 space-y-1">
          {user && (
            <div className="p-3 mb-2 rounded bg-[#111111] border border-[#292929] flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <UserIcon className="w-4 h-4 text-[#39FF88]" />
                <span className="font-semibold text-[#F5F5F5]">{user.full_name}</span>
              </div>
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  handleLogout();
                }}
                className="text-[#FF525C] flex items-center gap-1 font-medium"
              >
                <LogOut className="w-3.5 h-3.5" /> Logout
              </button>
            </div>
          )}

          {navItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setMobileMenuOpen(false)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded text-sm font-medium ${
                  active
                    ? 'bg-[#181818] text-[#39FF88] border border-[#292929]'
                    : 'text-[#A3A3A3] hover:text-[#F5F5F5] hover:bg-[#111111]'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-[#39FF88]' : 'text-[#A3A3A3]'}`} />
                {item.label}
              </Link>
            );
          })}

          {!user && (
            <div className="pt-2 flex flex-col gap-2">
              <Link
                to="/login"
                onClick={() => setMobileMenuOpen(false)}
                className="w-full flex justify-center items-center gap-2 py-2.5 rounded border border-[#292929] text-xs font-semibold text-[#F5F5F5]"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                onClick={() => setMobileMenuOpen(false)}
                className="w-full flex justify-center items-center gap-2 py-2.5 rounded bg-[#39FF88] text-[#050505] font-semibold text-xs"
              >
                Create Account
              </Link>
            </div>
          )}
        </div>
      )}
    </header>
  );
};
