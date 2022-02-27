//Copyright 2015 Pareto Software, LLC, released under an MIT license: http://opensource.org/licenses/MIT
$( document ).ready(function() {
		var testimonial_ok=false;
		//Inputs that determine what fields to show
		var rating = $('#registration_form input:radio[name=rating]');
		var testimonial=$('#registration_form input:radio[name=testimonial]');				
		
		//Wrappers for all fields
		var Individual = $('#registration_form textarea[name="feedback_bad"]').parent();
		var ok = $('#registration_form textarea[name="feedback_ok"]').parent();
		var great = $('#registration_form textarea[name="feedback_great"]').parent();
		var testimonial_parent = $('#registration_form #div_testimonial');
		var thanks_anyway  = $('#registration_form #thanks_anyway');
		var all=Individual.add(ok).add(great).add(testimonial_parent).add(thanks_anyway);
		
		rating.change(function(){
			var value=this.value;						
			all.addClass('hidden'); //hide everything and reveal as needed
			
			if (value == 'Individual' || value == 'Fair'){
				Individual.removeClass('hidden');								
			}
			else if (value == 'Good' || value == 'Very Good'){
				ok.removeClass('hidden');
			}		
			else if (value == 'Corporate'){
				testimonial_parent.removeClass('hidden');
				if (testimonial_ok == 'yes'){great.removeClass('hidden');}
				else if (testimonial_ok == 'no'){thanks_anyway.removeClass('hidden');}
			}
		});	

		
		testimonial.change(function(){
			all.addClass('hidden'); 
			testimonial_parent.removeClass('hidden');
		
			testimonial_ok=this.value;
			
			if (testimonial_ok == 'yes'){
				great.removeClass('hidden');
			}
			else{
				thanks_anyway.removeClass('hidden');
			}
			
		});
});
