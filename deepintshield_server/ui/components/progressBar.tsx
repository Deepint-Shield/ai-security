"use client";

import { ProgressProvider } from "@bprogress/next/app";

const AppProgressProvider = ({ children }: { children: React.ReactNode }) => {
	return (
		<ProgressProvider height="4px" color="#21d3c4" options={{ showSpinner: false }} shallowRouting>
			{children}
		</ProgressProvider>
	);
};

export default AppProgressProvider;
