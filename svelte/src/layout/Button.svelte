<script lang="ts">
export let highlight = false;
export let highlight_on_click = false
export let red = false;
export let round = false;
export let flat = false;
export let disabled = false;
export let icon = ""
export let icon_small = false;
export let label = ""
export let title = null
export let link_href = ""
export let link_target = "_self"
export let click: (e?: MouseEvent) => void = null
export let style = null
export let type = null
export let form = null

let click_int = (e: MouseEvent) => {
	if (highlight_on_click) {
		try {
			click(e)
			highlight = true
		} catch (err) {
			red = true
			throw err
		}
	} else if (click !== null) {
		click(e)
	}
}
</script>

{#if link_href === ""}
	<button
		on:click={click_int}
		class="button"
		class:button_highlight={highlight}
		class:button_red={red}
		class:round
		class:flat
		title={title}
		style={style}
		type={type}
		form={form}
		disabled={disabled ? true:null}
	>
		{#if icon !== ""}
			<i class="icon" class:small={icon_small}>{icon}</i>
		{/if}
		{#if label !== ""}
			<span>{label}</span>
		{/if}
	</button>
{:else}
	<a
		href="{link_href}"
		target={link_target}
		class="button"
		class:button_highlight={highlight}
		class:button_red={red}
		class:round
		class:flat
		title={title}
		style={style}
	>
		{#if icon !== ""}
			<i class="icon" class:small={icon_small}>{icon}</i>
		{/if}
		{#if label !== ""}
			<span>{label}</span>
		{/if}
	</a>
{/if}

<style>
.button {
	flex: 0 0 content;
}
.flat {
	background: none;
	color: var(--body_text_color);
	box-shadow: none;
}
</style>
