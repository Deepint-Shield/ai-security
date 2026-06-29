/**
 * Routing Rules Page
 * Main container for routing rules management
 */

import { RoutingRulesView } from "./views/routingRulesView";

export default function RoutingRulesPage() {
	return (
		<div className="workspace-page-shell">
			<RoutingRulesView />
		</div>
	);
}
