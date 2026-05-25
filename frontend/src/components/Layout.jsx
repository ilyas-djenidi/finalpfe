import React from 'react';
import Navbar from './Navbar';
import Sidebar from './Sidebar';

const Layout = ({ children }) => {
    return (
        <div className="h-screen bg-slate-50 dark:bg-slate-950 transition-colors duration-300 flex flex-col overflow-hidden">
            {/* Top Navbar */}
            <Navbar />

            {/* Body: Sidebar + Main Content */}
            <div className="flex flex-1 overflow-hidden">
                {/* Sidebar */}
                <Sidebar />

                {/* Main content */}
                <main className="flex-1 overflow-y-auto py-8 px-4 sm:px-6 lg:px-8">
                    <div className="max-w-7xl mx-auto">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default Layout;
