---
layout: page
title: Home
---

# A space on the internet for when I discover something cool

## Posts

<ul class="postlist">
	{% for post in site.posts %}
	<li>
		<a href="{{ post.url | relative_url }}"><h1>{{ post.title }}</h1></a>
	</li>
	{% endfor %}
</ul>
