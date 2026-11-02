import React, { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';

// Route-level code splitting — each page chunk is loaded on demand.
// This eliminates the ~790 KB monolithic bundle warning from Vite.
const LandingPage   = React.lazy(() => import('./pages/LandingPage').then(m => ({ default: m.LandingPage })));
const RegisterPage  = React.lazy(() => import('./pages/RegisterPage').then(m => ({ default: m.RegisterPage })));
const LoginPage     = React.lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })));
const ScannerPage   = React.lazy(() => import('./pages/ScannerPage').then(m => ({ default: m.ScannerPage })));
const ResultsPage   = React.lazy(() => import('./pages/ResultsPage').then(m => ({ default: m.ResultsPage })));
const DashboardPage = React.lazy(() => import('./pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const HistoryPage   = React.lazy(() => import('./pages/HistoryPage').then(m => ({ default: m.HistoryPage })));
const SettingsPage  = React.lazy(() => import('./pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const AboutPage     = React.lazy(() => import('./pages/AboutPage').then(m => ({ default: m.AboutPage })));

/** Minimal full-screen spinner shown while a lazy chunk is loading. */
const PageLoader: React.FC = () => (
  <div className="min-h-screen bg-[#050505] flex items-center justify-center">
    <div className="w-8 h-8 border-2 border-[#16C96A] border-t-transparent rounded-full animate-spin" />
  </div>
);

export const App: React.FC = () => {
  return (
    <Router>
      <AuthProvider>
        <div className="min-h-screen bg-[#050505] text-[#F5F5F5] flex flex-col font-sans selection:bg-[#16C96A] selection:text-[#050505]">
          <Navbar />
          <main className="flex-grow">
            <Suspense fallback={<PageLoader />}>
              <Routes>
                {/* Public Routes */}
                <Route path="/"         element={<LandingPage />} />
                <Route path="/register" element={<RegisterPage />} />
                <Route path="/login"    element={<LoginPage />} />
                <Route path="/ml-lab"   element={<Navigate to="/about" replace />} />
                <Route path="/about"    element={<AboutPage />} />

                {/* Protected Routes (Require Authenticated User Session) */}
                <Route
                  path="/scanner"
                  element={
                    <ProtectedRoute>
                      <ScannerPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/results/:scanId"
                  element={
                    <ProtectedRoute>
                      <ResultsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <DashboardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/history"
                  element={
                    <ProtectedRoute>
                      <HistoryPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/settings"
                  element={
                    <ProtectedRoute>
                      <SettingsPage />
                    </ProtectedRoute>
                  }
                />

                {/* Route aliases / Fallback */}
                <Route path="/scan"           element={<Navigate to="/scanner" replace />} />
                <Route path="/scans/:scanId"  element={<Navigate to="/results/:scanId" replace />} />
                <Route path="*"               element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </main>
          <Footer />
        </div>
      </AuthProvider>
    </Router>
  );
};

export default App;
