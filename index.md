---
layout: page
title: Home
---

# A space for all the things that interest me

## Posts

<ul class="postlist">
	{% for post in site.posts %}
	<li>
		<a href="{{ post.url | relative_url }}"><h1>{{ post.title }}</h1></a>
	</li>
	{% endfor %}
</ul>
