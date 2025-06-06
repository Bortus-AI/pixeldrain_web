<script lang="ts">
import PixeldrainLogo from "util/PixeldrainLogo.svelte";
import Button from "layout/Button.svelte";
import Euro from "util/Euro.svelte";
import { formatDataVolume } from "util/Formatting";
import { user } from "lib/UserStore";

let button: HTMLButtonElement
let dialog: HTMLDialogElement

export let no_login_label = "Pixeldrain"

// Hide the label if the screen is smaller than 800px
export let hide_name = true
export let hide_logo = false
export let style = ""
export let embedded = false
$: target = embedded ? "_blank" : "_self"

const open = () => {
	// Show the window so we can get the location
	dialog.showModal()

	const edge_offset = 5

	// Get the egdes of the screen, so the window does not spawn off-screen
	const window_rect = dialog.getBoundingClientRect()
	const max_left = window.innerWidth - window_rect.width - edge_offset
	const max_top = window.innerHeight - window_rect.height - edge_offset

	// Get the location of the button
	const button_rect = button.getBoundingClientRect()

	// Prevent the window from being glued to the edges
	const min_left = Math.max(button_rect.left, edge_offset)
	const min_top = Math.max(button_rect.bottom, edge_offset)

	// Place the window
	dialog.style.left = Math.round(Math.min(min_left, max_left)) + "px"
	dialog.style.top = Math.round(Math.min(min_top, max_top)) + "px"
}

// Close the dialog when the user clicks the background
const click = (e: MouseEvent) => {
	if (e.target === dialog) {
		dialog.close()
	}
}
</script>

<div class="wrapper">
	<button bind:this={button} on:click={open} class="button round" title="Menu" style={style}>
		{#if !hide_logo}
			<PixeldrainLogo style="height: 1.6em; width: 1.6em;"/>
		{/if}
		<span class="button_username" class:hide_name>
			{$user.username === "" ? no_login_label : $user.username}
		</span>
	</button>
</div>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
<dialog bind:this={dialog} on:click={click}>
	<div class="menu">
		{#if $user.username !== undefined && $user.username !== ""}

			<Button link_href="/user" link_target={target} icon="dashboard" label="Dashboard" />
			<div class="separator"></div>

			<div class="stats_table">
				<div>Subscription</div>
				<div>{$user.subscription.name}</div>

				{#if $user.subscription.type === "prepaid"}
					<div>Credit</div>
					<div><Euro amount={$user.balance_micro_eur}/></div>
				{/if}

				<div>Storage used</div>
				<div>{formatDataVolume($user.filesystem_storage_used, 3)}</div>
				<div>Transfer used</div>
				<div>{formatDataVolume($user.monthly_transfer_used, 3)}</div>
			</div>
			<div class="separator"></div>

			{#if $user.subscription.filesystem_access}
				<Button link_href="/d/me" link_target={target} icon="folder" label="My Filesystem"/>
			{:else}
				<Button link_href="/#pro" link_target={target} icon="star" label="Get Premium"/>
			{/if}

			<Button link_href="/filesystem" link_target={target} icon="description" label="Filesystem Guide"/>

			<div class="separator"></div>

			<Button link_href="/user/filemanager#files" link_target={target} icon="image" label="My Files"/>
			<Button link_href="/user/filemanager#lists" link_target={target} icon="photo_library" label="My Albums"/>

			<div class="separator"></div>

			<Button link_href="/user/settings" link_target={target} icon="settings" label="Account Settings"/>
			<Button link_href="/user/subscription" link_target={target} icon="shopping_cart" label="Subscription"/>
			<Button link_href="/user/prepaid/transactions" link_target={target} icon="receipt" label="Transactions"/>

			{#if $user.is_admin}
				<div class="separator"></div>
				<Button link_href="/admin" link_target={target} icon="admin_panel_settings" label="Admin Panel"/>
			{/if}
		{:else}
			<Button link_href="/" link_target={target} icon="home" label="Home"/>
			<Button link_href="/#pro" link_target={target} icon="star" label="Get Premium"/>
			<Button link_href="/login" link_target={target} icon="person" label="Log in"/>
			<Button link_href="/register" link_target={target} icon="person" label="Register"/>
		{/if}
	</div>
</dialog>

<style>
.wrapper {
	flex-grow: 0;
	flex-shrink: 0;
	display: inline-flex;
	align-self: center;
}

.button {
	flex: 0 0 content;
}
.button_username {
	margin: 0 4px;
}

dialog {
	background-color: var(--card_color);
	color: var(--body_text_color);
	border-radius: 8px;
	border: none;
	padding: 4px;
	margin: 0;
	box-shadow: 2px 2px 10px var(--shadow_color);
}
.menu {
	display: flex;
	flex-direction: column;
	max-width: 15em;
}
.separator {
	height: 1px;
	margin: 2px 0;
	width: 100%;
	background-color: var(--separator);
}
.stats_table {
	display: grid;
	grid-template-columns: auto auto;
	gap: 0.2em 1em;
	margin: 3px;
}

/* Hide username on small screen */
@media(max-width: 800px) {
	.hide_name {
		display: none;
	}
}
</style>
