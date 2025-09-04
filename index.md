---
layout: page
title: Home
---

# My space on the internet for cool stuff

## Posts

<ul class="postlist">
	{% for post in site.posts %}
	<li>
		<a href="{{ post.url | relative_url }}"><h1>{{ post.title }}</h1></a>
	</li>
	{% endfor %}
</ul>
