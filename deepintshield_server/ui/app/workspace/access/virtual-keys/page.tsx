"use client"

import VirtualKeysTable from "@/app/workspace/virtual-keys/views/virtualKeysTable"
import FullPageLoader from "@/components/fullPageLoader"
import { useDebouncedValue } from "@/hooks/useDebounce"
import {
	getErrorMessage,
	useGetCustomersQuery,
	useGetTeamsQuery,
	useGetVirtualKeysQuery,
} from "@/lib/store"
import { useAppSelector } from "@/lib/store/hooks"
import { selectActiveWorkspaceId } from "@/lib/store/slices/activeScopeSlice"
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib"
import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"

const POLLING_INTERVAL = 5000
const PAGE_SIZE = 25

export default function GovernanceVirtualKeysPage() {
	const hasVirtualKeysAccess = useRbac(RbacResource.VirtualKeys, RbacOperation.View)
	const hasTeamsAccess = useRbac(RbacResource.Teams, RbacOperation.View)
	const hasCustomersAccess = useRbac(RbacResource.Customers, RbacOperation.View)
	const shownErrorsRef = useRef(new Set<string>())

	const activeWorkspaceId = useAppSelector(selectActiveWorkspaceId)
	const [search, setSearch] = useState("")
	const [customerFilter, setCustomerFilter] = useState("")
	const [teamFilter, setTeamFilter] = useState("")
	const [offset, setOffset] = useState(0)

	const debouncedSearch = useDebouncedValue(search, 300)

	// Reset to first page when filters change (workspace switch included so
	// a user landing on a smaller scope doesn't sit past the result set).
	useEffect(() => {
		setOffset(0)
	}, [debouncedSearch, customerFilter, teamFilter, activeWorkspaceId])

	const {
		data: virtualKeysData,
		error: vkError,
		isLoading: vkLoading,
	} = useGetVirtualKeysQuery({
		limit: PAGE_SIZE,
		offset,
		search: debouncedSearch || undefined,
		customer_id: customerFilter || undefined,
		team_id: teamFilter || undefined,
		workspace_id: activeWorkspaceId || undefined,
	}, {
		skip: !hasVirtualKeysAccess,
		pollingInterval: POLLING_INTERVAL,
		// Revalidate on mount so a hard refresh reflects server truth rather than a
		// stale cross-session cache snapshot (see persistence.ts).
		refetchOnMountOrArgChange: true,
	})

	const {
		data: teamsData,
		error: teamsError,
		isLoading: teamsLoading,
	} = useGetTeamsQuery(undefined, {
		skip: !hasTeamsAccess,
		pollingInterval: POLLING_INTERVAL,
	})

	const {
		data: customersData,
		error: customersError,
		isLoading: customersLoading,
	} = useGetCustomersQuery(undefined, {
		skip: !hasCustomersAccess,
		pollingInterval: POLLING_INTERVAL,
	})

	const vkTotal = virtualKeysData?.total_count ?? 0

	// Snap offset back when total shrinks past current page (e.g. delete last item on last page)
	useEffect(() => {
		if (!virtualKeysData || offset < vkTotal) return
		setOffset(vkTotal === 0 ? 0 : Math.floor((vkTotal - 1) / PAGE_SIZE) * PAGE_SIZE)
	}, [vkTotal, offset])

	const isLoading = vkLoading || teamsLoading || customersLoading

	useEffect(() => {
		if (!vkError && !teamsError && !customersError) {
			shownErrorsRef.current.clear()
			return
		}
		const errorKey = `${!!vkError}-${!!teamsError}-${!!customersError}`
		if (shownErrorsRef.current.has(errorKey)) return
		shownErrorsRef.current.add(errorKey)
		if (vkError && teamsError && customersError) {
			toast.error("Failed to load governance data.")
		} else {
			if (vkError) toast.error(`Failed to load virtual keys: ${getErrorMessage(vkError)}`)
			if (teamsError) toast.error(`Failed to load teams: ${getErrorMessage(teamsError)}`)
			if (customersError) toast.error(`Failed to load members: ${getErrorMessage(customersError)}`)
		}
	}, [vkError, teamsError, customersError])

	if (isLoading) {
		return <FullPageLoader />
	}

	return (
		<div className="workspace-page-shell">
			<VirtualKeysTable
				virtualKeys={virtualKeysData?.virtual_keys || []}
				totalCount={virtualKeysData?.total_count || 0}
				teams={teamsData?.teams || []}
				customers={customersData?.customers || []}
				search={search}
				debouncedSearch={debouncedSearch}
				onSearchChange={setSearch}
				customerFilter={customerFilter}
				onCustomerFilterChange={setCustomerFilter}
				teamFilter={teamFilter}
				onTeamFilterChange={setTeamFilter}
				offset={offset}
				limit={PAGE_SIZE}
				onOffsetChange={setOffset}
			/>
		</div>
	)
}
